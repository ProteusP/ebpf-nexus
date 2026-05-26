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
 * <p>Supports two attachment methods depending on the tracepoint category:
 * <ul>
 *   <li><b>Raw tracepoints</b> ({@code cgroup}, {@code sched}, etc.) -
 *       loaded as {@code RAW_TRACEPOINT} and attached via
 *       {@code BPF_RAW_TRACEPOINT_OPEN}.</li>
 *   <li><b>Syscall tracepoints</b> ({@code syscalls:*}) -
 *       loaded as {@code TRACEPOINT} and attached via
 *       {@code perf_event_open()} because {@code BPF_RAW_TRACEPOINT_OPEN}
 *       does not support syscall tracepoints on kernels prior to 6.x.</li>
 * </ul>
 *
 * <p>Event delivery chain:
 * <ol>
 *   <li>eBPF program writes events to {@code BPF_MAP_TYPE_PERF_EVENT_ARRAY} ("events")</li>
 *   <li>Each CPU has a {@link PerfCounter} whose fd is stored in the map at key=cpu</li>
 *   <li>When eBPF calls {@code bpf_perf_event_output(&events, BPF_F_CURRENT_CPU, ...)},
 *       the kernel looks up {@code events[cpu]} to find the target fd and writes
 *       directly into that counter's ring buffer</li>
 *   <li>{@link RawPerfRingBuffer} reads the raw event data from the ring buffer via mmap</li>
 * </ol>
 */
public class PerfLoader implements ProgsLoader {

    private static final Logger log = LoggerFactory.getLogger(PerfLoader.class);

    /** Number of data pages per CPU ring buffer */
     private final int dataPages;

    /** Directory where compiled {@code .o} files reside. */
    private final String bpfObjectDir;

    /** Debugfs mount point for reading tracepoint IDs. */
    private static final String DEBUGFS = "/sys/kernel/debug";

    /** Syscall tracepoints have category "syscalls". */
    private static final String SYSCALLS_CATEGORY = "syscalls";

    /** Invalid file descriptor constant. */
    private static final int INVALID_FD = -1;

    /** Map from tracepoint name to its full "category:name" specification. */
    private final Map<String, String> tracepointSpecs;

    private final List<PerfCounter> perfCounters = new ArrayList<>();
    private final List<Handle> tracepointLinks = new ArrayList<>();
    private final List<PerfCounter> syscallAttachCounters = new ArrayList<>();
    private final List<BpfProg> loadedPrograms = new ArrayList<>();

    private BpfMap perfEventArray;
    private RawPerfRingBuffer[] ringBuffers;

    /**
     * Creates a loader for the given list of tracepoints.
     *
     * @param tracepoints tracepoint names in {@code "category:name"} format,
     *                    e.g. {@code "cgroup:cgroup_attach_task"},
     *                    {@code "syscalls:sys_enter_sched_setattr"}
     */
    public PerfLoader(List<String> tracepoints, String bpfObjectDir, int dataPages) {
        this.tracepointSpecs = new LinkedHashMap<>();
        for (String tp : tracepoints) {
            String[] parts = tp.split(":");
            String name = parts[1];
            tracepointSpecs.put(name, tp);
        }
        this.bpfObjectDir = bpfObjectDir;
        this.dataPages = dataPages;
    }

    public RawPerfRingBuffer[] getRingBuffers() {
        return ringBuffers;
    }

    @Override
    public void loadAll() {
        try {
            // Step 1 - create the shared perf event array map (once for all programs)
            perfEventArray = BpfMap.newPerfEventArray("events", 0);
            if (perfEventArray == null) {
                throw new IOException("Failed to create perf event array map");
            }
            log.info("Perf event array created, fd={}", perfEventArray.fd());

            // Step 2 - create per-CPU perf counters backed by ring buffers,
            // and store each counter's fd into the perf event array map.
            // This MUST be done BEFORE loading programs to avoid race conditions
            // where eBPF programs try to write to empty map slots.
            int cpuCount = Cpus.COUNT;
            ringBuffers = new RawPerfRingBuffer[cpuCount];

            for (int cpu = 0; cpu < cpuCount; cpu++) {
                byte[] key = BpfMap.bytes(cpu);

                if (!Cpus.ONLINE.get(cpu)) {
                    // Store invalid fd for offline CPUs to prevent eBPF from trying to use them
                    byte[] value = BpfMap.bytes(INVALID_FD);
                    boolean ok = perfEventArray.put(key, value);
                    if (!ok) {
                        log.warn("Failed to store invalid fd for offline CPU {}", cpu);
                    }
                    log.debug("CPU {} is offline, marked with invalid fd", cpu);
                    continue;
                }

                // Open perf counter with freq(1) - required for ring buffer allocation.
                // The freq value itself is irrelevant; it only triggers useRingBuffer=true
                // inside Perf.createRingBuffer(). eBPF controls when events are sent.
                PerfCounter counter = Perf.open(
                        PerfEvent.SW_BPF_OUTPUT,
                        Perf.ANY_PID,
                        cpu,
                        PerfOption.pages(dataPages),
                        PerfOption.freq(1)
                );

                if (counter == null) {
                    throw new IOException("Failed to open perf counter for CPU " + cpu);
                }

                log.info("CPU {} counter opened, fd={}", cpu, counter.getFd());

                // Store counter fd into the perf event array at key = cpu.
                // When eBPF calls bpf_perf_event_output(&events, BPF_F_CURRENT_CPU, ...),
                // the kernel reads events[cpu] to find this fd and writes data into
                // the counter's ring buffer.
                byte[] value = BpfMap.bytes(counter.getFd());
                boolean ok = perfEventArray.put(key, value);
                if (!ok) {
                    counter.close();
                    throw new IOException("Failed to store counter fd in perf event array for CPU " + cpu);
                }

                ringBuffers[cpu] = new RawPerfRingBuffer(counter, dataPages);
                perfCounters.add(counter);
            }

            // Step 3 - load and attach each tracepoint individually.
            // All map slots are now properly initialized, so eBPF programs can safely write.
            for (Map.Entry<String, String> entry : tracepointSpecs.entrySet()) {
                loadAndAttachTracepoint(entry.getKey(), entry.getValue());
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
            try {
                perfEventArray.close();
            } catch (Exception closeEx) {
                log.warn("Error closing perf event array after failed init", closeEx);
            }
        }

        // Also close any counters that were already created
        for (PerfCounter pc : perfCounters) {
            if (pc != null) {
                try {
                    pc.close();
                } catch (Exception closeEx) {
                    log.warn("Error closing perf counter after failed init", closeEx);
                }
            }
        }
        }
    }

    /**
     * Attaches a non-syscall tracepoint using {@code BPF_RAW_TRACEPOINT_OPEN}.
     * Works for categories like {@code cgroup}, {@code sched}, etc.
     */
    private void attachRawTracepoint(String name) throws IOException {
        String objectPath = objectPathFor(name);
        BpfProg prog = null;

        try {
            prog = BpfProg.load(objectPath, ProgType.RAW_TRACEPOINT);
            if (prog == null) {
                throw new IOException("Failed to load eBPF program from " + objectPath);
            }
            loadedPrograms.add(prog);
            log.info("eBPF program loaded: {} ({})", prog.name, objectPath);

            Handle link = prog.attachRawTracepoint(name);
            if (link == null) {
                throw new IOException("Failed to attach raw tracepoint: " + name);
            }
            tracepointLinks.add(link);
            log.info("Attached to raw tracepoint: {}", name);

        } catch (IOException e) {
            if (prog != null) {
                loadedPrograms.remove(prog);
                prog.close();
            }
            throw e;
        }
    }

    /**
     * Attaches a syscall tracepoint using {@code perf_event_open()}.
     * {@code BPF_RAW_TRACEPOINT_OPEN} does not support syscall tracepoints
     * on kernels &lt; 6.x, so we fall back to the legacy method:
     * load as {@code TRACEPOINT}, read the numeric ID from debugfs,
     * open a perf event for that ID, and attach the program via
     * {@code PERF_EVENT_IOC_SET_BPF}.
     */
    private void attachSyscallTracepoint(String name) throws IOException {
        String objectPath = objectPathFor(name);
        BpfProg prog = null;
        PerfCounter tpCounter = null;

        try {
            // Read numeric tracepoint ID from debugfs
            String idPath = DEBUGFS + "/tracing/events/syscalls/" + name + "/id";
            String idStr = Files.readString(Path.of(idPath)).trim();
            int tpId = Integer.parseInt(idStr);
            log.info("Syscall tracepoint id for {}: {}", name, tpId);

            // Load eBPF program as TRACEPOINT (not RAW_TRACEPOINT)
            prog = BpfProg.load(objectPath, ProgType.TRACEPOINT);
            if (prog == null) {
                throw new IOException("Failed to load eBPF program from " + objectPath);
            }
            loadedPrograms.add(prog);
            log.info("eBPF program loaded: {} ({})", prog.name, objectPath);

            // Open a perf event for this tracepoint.
            PerfEvent tpEvent = PerfEvent.tracepoint(tpId);
            tpCounter = Perf.open(
                    tpEvent,
                    Perf.ANY_PID,
                    0
            );

            if (tpCounter == null) {
                throw new IOException("Failed to open perf event for syscall tracepoint: " + name);
            }

            // Attach the eBPF program to the perf event
            tpCounter.attachBpf(prog.fd());

            syscallAttachCounters.add(tpCounter);
            log.info("Attached to syscall tracepoint: {}", name);

        } catch (IOException e) {
            if (tpCounter != null) {
                tpCounter.close();
            }
            if (prog != null) {
                loadedPrograms.remove(prog);
                prog.close();
            }
            throw e;
        }
    }

    /**
     * Resolves the object file path for a given tracepoint name.
     */
    private String objectPathFor(String name) {
        return bpfObjectDir + "/" + name + ".o";
    }

    @Override
    public void unloadAll() {
        // Close ring buffers first (they may be actively reading)
        if (ringBuffers != null) {
            for (RawPerfRingBuffer rb : ringBuffers) {
                if (rb != null) {
                    try {
                        rb.close();
                    } catch (Exception e) {
                        log.warn("Error closing ring buffer", e);
                    }
                }
            }
        }

        // Close perf counters
        for (PerfCounter pc : perfCounters) {
            if (pc != null) {
                try {
                    pc.close();
                } catch (Exception e) {
                    log.warn("Error closing perf counter", e);
                }
            }
        }

        // Close syscall attach counters
        for (PerfCounter pc : syscallAttachCounters) {
            if (pc != null) {
                try {
                    pc.close();
                } catch (Exception e) {
                    log.warn("Error closing syscall perf counter", e);
                }
            }
        }

        // Close tracepoint links
        for (Handle link : tracepointLinks) {
            if (link != null) {
                try {
                    link.close();
                } catch (Exception e) {
                    log.warn("Error closing tracepoint link", e);
                }
            }
        }

        // Close loaded programs
        for (BpfProg prog : loadedPrograms) {
            if (prog != null) {
                try {
                    prog.close();
                } catch (Exception e) {
                    log.warn("Error closing BPF program", e);
                }
            }
        }

        // Close perf event array map
        if (perfEventArray != null) {
            try {
                perfEventArray.close();
            } catch (Exception e) {
                log.warn("Error closing perf event array", e);
            }
        }

        log.info("Unloaded all components");
    }

    private void loadAndAttachTracepoint(String name, String fullSpec) {
    String category = fullSpec.split(":")[0];
    try {
        if (SYSCALLS_CATEGORY.equals(category)) {
            attachSyscallTracepoint(name);
        } else {
            attachRawTracepoint(name);
        }
    } catch (IOException e) {
        log.error("Failed to load/attach tracepoint: {}", fullSpec, e);
        // Continue with other tracepoints
    }
}
}