package ebpf.nexus.readers;

import ebpf.nexus.core.EventsReader;
import ebpf.nexus.core.EventHandler;
import ebpf.nexus.model.Event;

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
    private static final int POLL_INTERVAL_MS = 10;

    /** Maximum size of a single raw event - used for the reusable buffer. */
    private static final int MAX_EVENT_SIZE = 4096;

    private EventHandler handler;
    private volatile boolean running;

    private final RawPerfRingBuffer[] ringBuffers;
    private final int cpuCount;

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

                    int len = ringBuffers[cpu].readRaw(buffer);
                    if (len > 0) {
                        gotEvents = true;

                        Event event = new Event();
                        event.readFromBytes(buffer, 0);

                        if (handler != null) {
                            handler.handle(event);
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