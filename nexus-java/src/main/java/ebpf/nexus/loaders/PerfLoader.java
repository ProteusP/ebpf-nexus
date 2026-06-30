package ebpf.nexus.loaders;

import ebpf.nexus.core.ProgsLoader;
import ebpf.nexus.readers.RawPerfRingBuffer;
import one.nio.os.bpf.BpfMap;
import one.nio.os.bpf.BpfProg;
import one.nio.os.bpf.Handle;
import one.nio.os.bpf.ProgType;
import one.nio.os.perf.Perf;
import one.nio.os.perf.PerfCounter;
import one.nio.os.perf.PerfEvent;
import one.nio.os.perf.PerfOption;
import one.nio.os.Cpus;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads eBPF programs and configures perf_event infrastructure
 * for receiving events from kernel tracepoints.
 *
 * <p>Two attachment methods:
 * <ul>
 *   <li><b>Raw tracepoints</b> ({@code cgroup:*}) -
 *       loaded as {@code RAW_TRACEPOINT}, attached via {@code BPF_RAW_TRACEPOINT_OPEN}.</li>
 *   <li><b>Sys_enter</b> - loaded as {@code TRACEPOINT}, attached via
 *       {@code perf_event_open()} + {@code PERF_EVENT_IOC_SET_BPF}.
 *       Uses a single program that filters by syscall number internally.</li>
 * </ul>
 */
public class PerfLoader implements ProgsLoader {

    private static final Logger log = LoggerFactory.getLogger(PerfLoader.class);

    private final int dataPages;
    private final String bpfObjectDir;

    private static final String DEBUGFS = "/sys/kernel/debug";
    private static final int INVALID_FD = -1;
    private static final String PIN_PATH = "/sys/fs/bpf/events";

    /** Name of the combined syscall program - attached via perf_event_open. */
    private static final String SYSCALL_PROG_NAME = "sys_enter";

    private final Map<String, String> tracepointSpecs;

    private final List<PerfCounter> perfCounters = new ArrayList<>();
    private final List<Handle> tracepointLinks = new ArrayList<>();
    private final List<PerfCounter> syscallAttachCounters = new ArrayList<>();
    private final List<BpfProg> loadedPrograms = new ArrayList<>();
    private final List<Long> trackedCgroups;

    private BpfMap perfEventArray;
    private RawPerfRingBuffer[] ringBuffers;

    public PerfLoader(List<String> tracepoints, String bpfObjectDir, int dataPages, List<Long> trackedCgroups) {
        this.tracepointSpecs = new LinkedHashMap<>();
        for (String tp : tracepoints) {
            String[] parts = tp.split(":");
            String name = parts[1];
            tracepointSpecs.put(name, tp);
        }
        this.bpfObjectDir = bpfObjectDir;
        this.dataPages = dataPages;
        this.trackedCgroups = trackedCgroups;
    }

    public RawPerfRingBuffer[] getRingBuffers() {
        return ringBuffers;
    }

    @Override
    public void loadAll() {
        try {
            int cpuCount = Cpus.COUNT;
            ringBuffers = new RawPerfRingBuffer[cpuCount];

            // Step 1 - load the first eBPF program
            Map.Entry<String, String> firstEntry = tracepointSpecs.entrySet().iterator().next();
            String firstName = firstEntry.getKey();

            BpfProg firstProg = loadProgram(firstName);
            log.info("First eBPF program loaded: {} ({})", firstProg.name, objectPathFor(firstName));

            // Step 2 - open the pinned map created by the first program
            try {
                perfEventArray = BpfMap.getPinned(PIN_PATH);
                log.info("Opened pinned events map, fd={}", perfEventArray.fd());
            } catch (IOException e) {
                throw new IOException(
                        "Failed to open pinned events map at " + PIN_PATH + ". "
                        + "Ensure every .bpf.c declares __uint(pinning, LIBBPF_PIN_BY_NAME).", e);
            }

            // Step 2.5 - create cgroup filter map BEFORE loading remaining programs
            // so libbpf can find it by name and reuse it
            String cgroupPinPath = "/sys/fs/bpf/tracked_cgroups"; // TODO: мб вынести куда-то
            BpfMap trackedMap = null;

            try {
                trackedMap = BpfMap.newMap(
                    one.nio.os.bpf.MapType.HASH,
                    8,   // key_size: u64 cgroup_id
                    1,   // value_size: u8 flag
                    256, // max_entries
                    "tracked_cgroups",
                    0
                );
                trackedMap.pin(cgroupPinPath);
                log.info("Cgroup filter map created and pinned to {}", cgroupPinPath);
            } catch (IOException e) {
                // Map may already be pinned from a previous run
                log.debug("Cgroup filter map already exists, reopening: {}", cgroupPinPath);
                try {
                    trackedMap = BpfMap.getPinned(cgroupPinPath);
                } catch (IOException ex) {
                    log.error("Failed to open cgroup filter map", ex);
                }
            }

            if (trackedMap != null) {
                byte[] flag = new byte[]{1};
                if (trackedCgroups != null && !trackedCgroups.isEmpty()) {
                    for (long cgroupId : trackedCgroups) {
                        trackedMap.put(BpfMap.bytes(cgroupId), flag);
                    }
                    log.info("Cgroup filter enabled: {} cgroups tracked", trackedCgroups.size());
                } else {
                    // Sentinel key 0 -> track all
                    trackedMap.put(BpfMap.bytes(0L), flag);
                    log.info("Cgroup filter: tracking all (sentinel set)");
                }
            }

            // Step 3 - fill every CPU slot with a perf counter fd
            for (int cpu = 0; cpu < cpuCount; cpu++) {
                byte[] key = BpfMap.bytes(cpu);

                if (!Cpus.ONLINE.get(cpu)) {
                    byte[] value = BpfMap.bytes(INVALID_FD);
                    boolean ok = perfEventArray.put(key, value);
                    if (!ok) {
                        log.warn("Failed to store invalid fd for offline CPU {}", cpu);
                    }
                    log.debug("CPU {} is offline, marked with invalid fd", cpu);
                    continue;
                }

                PerfCounter counter = Perf.open(
                        PerfEvent.SW_BPF_OUTPUT,
                        Perf.ANY_PID,
                        cpu,
                        PerfOption.pages(dataPages),
                        PerfOption.freq(1),
                        PerfOption.SAMPLE_RAW
                );

                if (counter == null) {
                    throw new IOException("Failed to open perf counter for CPU " + cpu);
                }

                log.info("CPU {} counter opened, fd={}", cpu, counter.getFd());

                byte[] value = BpfMap.bytes(counter.getFd());
                boolean ok = perfEventArray.put(key, value);
                if (!ok) {
                    counter.close();
                    throw new IOException("Failed to store counter fd in perf event array for CPU " + cpu);
                }

                ringBuffers[cpu] = new RawPerfRingBuffer(counter, dataPages);
                perfCounters.add(counter);
            }

            // Step 4 - attach the first program
            attachProgram(firstProg, firstName);

            // Step 5 - load and attach remaining programs
            boolean firstSkipped = false;
            for (Map.Entry<String, String> entry : tracepointSpecs.entrySet()) {
                if (!firstSkipped) {
                    firstSkipped = true;
                    continue;
                }

                String name = entry.getKey();
                String fullSpec = entry.getValue();

                try {
                    BpfProg prog = loadProgram(name);
                    attachProgram(prog, name);
                } catch (IOException e) {
                    log.error("Failed to load/attach tracepoint: {}", fullSpec, e);
                }
            }

            if (tracepointLinks.isEmpty() && syscallAttachCounters.isEmpty()) {
                log.error("No tracepoints were attached, aborting");
                return;
            }

            log.info("All tracepoints loaded and configured ({} raw + {} syscall, {} CPUs)",
                    tracepointLinks.size(), syscallAttachCounters.size(),
                    ringBuffers.length);

        } catch (IOException e) {
            log.error("Failed to initialize perf infrastructure", e);

            if (perfEventArray != null) {
                try { perfEventArray.close(); } catch (Exception ex) { log.warn("Error closing perf event array", ex); }
            }
            for (PerfCounter pc : perfCounters) {
                if (pc != null) {
                    try { pc.close(); } catch (Exception ex) { log.warn("Error closing perf counter", ex); }
                }
            }
        }
    }

    /**
     * Loads a program as RAW_TRACEPOINT (for cgroup) or TRACEPOINT (for sys_enter).
     */
    private BpfProg loadProgram(String name) throws IOException {
        ProgType type = SYSCALL_PROG_NAME.equals(name) ? ProgType.TRACEPOINT : ProgType.RAW_TRACEPOINT;
        String objectPath = objectPathFor(name);
        BpfProg prog = BpfProg.load(objectPath, type);
        if (prog == null) {
            throw new IOException("Failed to load eBPF program from " + objectPath);
        }
        loadedPrograms.add(prog);
        log.info("eBPF program loaded: {} ({})", prog.name, objectPath);
        return prog;
    }

    /**
     * Attaches a program: sys_enter via perf_event_open, others via BPF_RAW_TRACEPOINT_OPEN.
     */
    private void attachProgram(BpfProg prog, String name) throws IOException {
        log.info("Attaching raw tracepoint: name='{}'", name);
        if (SYSCALL_PROG_NAME.equals(name)) {
            attachSyscallTracepoint(prog, name);
        } else {
            Handle link = prog.attachRawTracepoint(name);
            if (link == null) {
                throw new IOException("Failed to attach raw tracepoint: " + name);
            }
            tracepointLinks.add(link);
            log.info("Attached to raw tracepoint: {}", name);
        }
    }

    /**
     * Attaches the sys_enter program via perf_event_open + PERF_EVENT_IOC_SET_BPF.
     */
    private void attachSyscallTracepoint(BpfProg prog, String name) throws IOException {
        PerfCounter tpCounter = null;

        try {
            String idPath = DEBUGFS + "/tracing/events/raw_syscalls/" + name + "/id";
            String idStr = Files.readString(Path.of(idPath)).trim();
            int tpId = Integer.parseInt(idStr);
            log.info("Syscall tracepoint id for {}: {}", name, tpId);

            PerfEvent tpEvent = PerfEvent.tracepoint(tpId);
            tpCounter = Perf.open(tpEvent, Perf.ANY_PID, 0);

            if (tpCounter == null) {
                throw new IOException("Failed to open perf event for syscall tracepoint: " + name);
            }

            tpCounter.attachBpf(prog.fd());
            syscallAttachCounters.add(tpCounter);
            log.info("Attached to syscall tracepoint: {}", name);

        } catch (IOException e) {
            if (tpCounter != null) {
                tpCounter.close();
            }
            throw e;
        }
    }

    private String objectPathFor(String name) {
        return bpfObjectDir + "/" + name + ".o";
    }

    @Override
    public void unloadAll() {
        if (ringBuffers != null) {
            for (RawPerfRingBuffer rb : ringBuffers) {
                if (rb != null) {
                    try { rb.close(); } catch (Exception e) { log.warn("Error closing ring buffer", e); }
                }
            }
        }

        for (PerfCounter pc : perfCounters) {
            if (pc != null) {
                try { pc.close(); } catch (Exception e) { log.warn("Error closing perf counter", e); }
            }
        }

        for (PerfCounter pc : syscallAttachCounters) {
            if (pc != null) {
                try { pc.close(); } catch (Exception e) { log.warn("Error closing syscall perf counter", e); }
            }
        }

        for (Handle link : tracepointLinks) {
            if (link != null) {
                try { link.close(); } catch (Exception e) { log.warn("Error closing tracepoint link", e); }
            }
        }

        for (BpfProg prog : loadedPrograms) {
            if (prog != null) {
                try { prog.close(); } catch (Exception e) { log.warn("Error closing BPF program", e); }
            }
        }

        if (perfEventArray != null) {
            try { perfEventArray.close(); } catch (Exception e) { log.warn("Error closing perf event array", e); }
        }

        try {
            Files.deleteIfExists(Path.of(PIN_PATH));
            log.debug("Deleted pinned map file: {}", PIN_PATH);
        } catch (IOException e) {
            log.warn("Failed to delete pinned map file: {}", PIN_PATH, e);
        }

        try {
            Files.deleteIfExists(Path.of("/sys/fs/bpf/tracked_cgroups")); // TODO: точно вынести отдельно :)
            log.debug("Deleted cgroup filter map pin");
        } catch (IOException e) {
            log.warn("Failed to delete cgroup filter map pin", e);
        }

        log.info("Unloaded all components");
    }
}