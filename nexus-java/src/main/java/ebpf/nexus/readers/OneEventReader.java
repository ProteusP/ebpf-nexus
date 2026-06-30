package ebpf.nexus.readers;

import ebpf.nexus.core.EventsReader;
import ebpf.nexus.core.EventHandler;
import ebpf.nexus.model.Event;
import ebpf.nexus.metrics.Metrics;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Polls per-CPU perf ring buffers for eBPF events and forwards them
 * to an {@link EventHandler}.
 *
 * <p>Runs on a single thread that iterates over all online CPUs.
 * When no events are available the thread sleeps for
 * {@value #POLL_INTERVAL_MS} ms to avoid busy-waiting.
 */
public class OneEventReader implements EventsReader {

    private static final Logger log = LoggerFactory.getLogger(OneEventReader.class);

    /** Sleep duration between empty poll cycles, in milliseconds. */
    private static final int POLL_INTERVAL_MS = 50;

    /** Maximum size of a single raw event - used for the reusable buffer. */
    private static final int MAX_EVENT_SIZE = 4096;

    private EventHandler handler;
    private volatile boolean running;

    private final RawPerfRingBuffer[] ringBuffers;
    private final int cpuCount;

    private long nanoOffset;
    private boolean calibrated;

    private final Event reusableEvent = new Event();

    private static final String[] TP_LABELS = {"0", "1", "2", "3", "4", "5"};

    /**
     * @param ringBuffers per-CPU ring buffers (index = CPU id, null if CPU is offline)
     */
    public OneEventReader(RawPerfRingBuffer[] ringBuffers) {
        this.ringBuffers = ringBuffers;
        this.cpuCount = ringBuffers.length;
    }

    @Override
    public void start() {
        running = true;

        // Reusable buffer to avoid allocations in the hot path.
        byte[] buffer = new byte[MAX_EVENT_SIZE];

        log.info("Event reader started, {} CPUs", cpuCount);

        while (running) {
            try {
                boolean gotEvents = false;

                for (int cpu = 0; cpu < cpuCount; cpu++) {
                    if (ringBuffers[cpu] == null) continue;

                    int len;
                    while ((len = ringBuffers[cpu].readRaw(buffer)) > 0) {
                        gotEvents = true;

                        reusableEvent.readFromBytes(buffer, 0);
                        Metrics.eventsTotal.labels(TP_LABELS[reusableEvent.getTpId()]).inc();
                        if (!calibrated) {
                            nanoOffset = reusableEvent.getTimestamp() - System.nanoTime();
                            calibrated = true;
                            log.info("Latency calibrated: offset={}ns", nanoOffset);
                        }
                        
                        // Record metrics with calibrated latency
                        if (calibrated) {
                            long latency = System.nanoTime() + nanoOffset - reusableEvent.getTimestamp();
                            if (latency > 0) {
                                Metrics.processingLatency.observe(latency / 1e9);
                            }
                        }
                        log.debug("Event is {}",reusableEvent);
                        if (handler != null) {
                            handler.handle(reusableEvent);
                        }
                    }
                }

                if (!gotEvents) {
                    Thread.sleep(POLL_INTERVAL_MS);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error reading events", e);
            }
        }

        log.info("Event reader stopped");
    }

    @Override
    public void stop() {
        running = false;
    }

    @Override
    public void setHandler(EventHandler handler) {
        this.handler = handler;
    }
}