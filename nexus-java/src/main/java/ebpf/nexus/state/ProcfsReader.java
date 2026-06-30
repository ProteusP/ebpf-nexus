package ebpf.nexus.state;

import ebpf.nexus.model.StateSnapshot;
import ebpf.nexus.model.ProcessInfo;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reads the full system state from {@code /proc} filesystem.
 *
 * <p>Provides a complete snapshot of all processes with their scheduler
 * attributes and cgroup associations. This snapshot is used as the
 * baseline that eBPF events are applied to.
 *
 * <p>The read is NOT atomic - processes may appear or disappear during
 * iteration. Events buffered during the read are applied afterwards
 * to bring the snapshot up to date.
 */
public class ProcfsReader {

    private static final Logger log = LoggerFactory.getLogger(ProcfsReader.class);

    /**
     * Reads the full system state from procfs.
     *
     * @return a complete snapshot of processes and cgroups
     * @throws IOException if a critical procfs entry cannot be read
     */
    public StateSnapshot readFullState() throws IOException {
        long startTime = System.currentTimeMillis();

        StateSnapshot snapshot = new StateSnapshot();

        readAllProcesses(snapshot);

        snapshot.setSnapshotTimestamp(System.currentTimeMillis());
        log.info("Snapshot completed in {}ms, {} processes",
                snapshot.getSnapshotTimestamp() - startTime,
                snapshot.getProcesses().size());

        return snapshot;
    }

    /**
     * Iterates over {@code /proc/[pid]} directories and reads process info.
     * Processes that die between listing and reading are silently skipped.
     */
    private void readAllProcesses(StateSnapshot snapshot) {
        File procDir = new File("/proc");

        File[] processes = procDir.listFiles(f -> {
            if (!f.isDirectory()) return false;
            try {
                Integer.parseInt(f.getName());
                return true;
            } catch (NumberFormatException e) {
                return false;
            }
        });

        if (processes == null) return;

        for (File processDir : processes) {
            try {
                int pid = Integer.parseInt(processDir.getName());
                ProcessInfo info = readProcessInfo(pid);
                if (info != null) {
                    snapshot.getProcesses().put(pid, info);
                }
            } catch (Exception e) {
                // Process died between listFiles and readProcessInfo - skip
            }
        }
    }

    /**
     * Reads scheduler and cgroup information for a single process.
     *
     * <p>Parses {@code /proc/[pid]/stat} for scheduler attributes and
     * {@code /proc/[pid]/cgroup} for cgroup membership.
     *
     * <p>The {@code comm} field in stat may contain spaces and parentheses,
     * e.g. {@code 123 (my process (child)) R ...}. The correct parsing
     * strategy is to find the outermost parentheses rather than splitting
     * on whitespace.
     *
     * @param pid process ID
     * @return populated {@link ProcessInfo} or {@code null} if the process
     *         terminated during reading
     * @throws IOException if procfs entries are malformed
     */
    private ProcessInfo readProcessInfo(int pid) throws IOException {
        ProcessInfo info = new ProcessInfo();
        info.setPid(pid);

        // Read /proc/[pid]/stat
        // Format: pid (comm) state ppid ... nice ... policy ...
        Path statPath = Path.of("/proc/" + pid + "/stat");
        String statContent;
        try {
            statContent = Files.readString(statPath);
        } catch (IOException e) {
            // Process died between listFiles and read - skip
            return null;
        }

        int leftParen = statContent.indexOf('(');
        int rightParen = statContent.lastIndexOf(')');
        if (leftParen == -1 || rightParen == -1 || rightParen <= leftParen) {
            return null;
        }

        // Extract comm between the outermost parentheses
        info.setComm(statContent.substring(leftParen + 1, rightParen));

        // Split everything after ") " into fields
        // The format is: "pid (comm) state ppid pgrp session tty_nr tpgid flags
        //                  minflt cminflt majflt cmajflt utime stime cutime cstime
        //                  priority nice num_threads itrealvalue starttime vsize rss
        //                  rsslim startcode endcode startstack kstkesp kstkeip signal
        //                  blocked sigignore sigcatch wchan nswap cnswap exit_signal
        //                  processor rt_priority policy ..."
        String afterComm = statContent.substring(rightParen + 2); // skip ") "
        String[] rest = afterComm.split(" ");

        // Field indices after comm (0-based):
        // 0=state, 1=ppid, ..., 16=nice (field index 18 in full stat), ..., 38=policy (field index 40 in full stat)
        if (rest.length < 40) return null;

        info.setState(parseState(rest[0].charAt(0)));
        info.setPpid(Integer.parseInt(rest[1]));
        info.setNice(Integer.parseInt(rest[16]));
        info.setSchedulerPolicy(Integer.parseInt(rest[38]));

        // Read cgroup membership from /proc/[pid]/cgroup
        info.setCgroupId( readCgroupInode(pid));

        return info;
    }

    /**
     * Reads the cgroup inode for a process.
     *
     * <p>Uses the cgroup v2 hierarchy (controller 0) and resolves the
     * inode number of the cgroup directory as a stable identifier.
     * Falls back to path-based hash if the cgroupfs is not accessible.
     */
    private long readCgroupInode(int pid) {
        Path cgroupProcPath = Path.of("/proc/" + pid + "/cgroup");
        if (!Files.exists(cgroupProcPath)) {
            return 0;
        }

        try {
            String cgroupContent = Files.readString(cgroupProcPath);
            for (String line : cgroupContent.split("\n")) {
                if (line.isEmpty()) continue;

                String[] parts = line.split(":");
                if (parts.length < 3) continue;

                String cgroupPath = parts[2];
                if (cgroupPath == null || cgroupPath.isEmpty()) continue;

                Path fullCgroupPath = Path.of("/sys/fs/cgroup", cgroupPath);
                Long inode = readInode(fullCgroupPath);
                if (inode != null) {
                    return inode;
                }

                // Fallback: use path hash as identifier
                return cgroupPath.hashCode();
            }
        } catch (IOException e) {
            // Process died - skip
        }

        return 0;
    }

    /**
     * Reads the inode of a cgroup directory.
     *
     * @return inode number, or {@code null} if not available
     */
    private Long readInode(Path cgroupPath) {
        if (!Files.exists(cgroupPath)) {
            return null;
        }
        try {
            Object inode = Files.getAttribute(cgroupPath, "unix:ino");
            if (inode instanceof Long) {
                return (Long) inode;
            }
        } catch (Exception e) {
            // inode not available
        }
        return null;
    }

    /**
     * Converts the process state character from {@code /proc/[pid]/stat}
     * to a numeric code.
     */
    private int parseState(char state) {
        switch (state) {
            case 'R': return 1; // Running
            case 'S': return 2; // Sleeping (interruptible)
            case 'D': return 3; // Disk sleep (uninterruptible)
            case 'Z': return 4; // Zombie
            case 'T': return 5; // Stopped (by signal)
            case 't': return 6; // Tracing stop
            case 'X': return 7; // Dead
            default:  return 0; // Unknown
        }
    }
}