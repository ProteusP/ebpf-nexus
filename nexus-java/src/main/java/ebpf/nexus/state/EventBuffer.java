package ebpf.nexus.state;

import ebpf.nexus.model.Event;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe buffer for eBPF events collected during a snapshot cycle.
 *
 * <p>Events arriving while a full procfs snapshot is in progress are
 * stored here. Once the snapshot completes, buffered events are drained
 * and applied to the fresh state, ensuring no updates are lost.
 */
public class EventBuffer {

    private final List<Event> buffer = new CopyOnWriteArrayList<>();
    private volatile long nanoOffset;
    
    /**
     * Clears the buffer at the start of a new snapshot cycle.
     */
    public void startBuffering() {
        buffer.clear();
    }

    /**
     * Adds an event to the buffer. Thread-safe.
     */
    public void addEvent(Event event) {
        buffer.add(event);
    }

    /**
     * Sets the offset between eBPF timestamps and Java nanoTime.
     * Called when the first event arrives.
     */
    public void calibrate(long bpfTimestampNanos) {
        this.nanoOffset = bpfTimestampNanos - System.nanoTime();
    }

    /**
     * Drains all events with a timestamp greater than the given threshold.
     *
     * @param sinceNanoTime keep only events newer than this
     * @return list of matching events in insertion order
     */
    public List<Event> drain(long sinceNanoTime) {
        long thresholdNanos = sinceNanoTime + nanoOffset;
        List<Event> result = new ArrayList<>();

        for (Event event : buffer) {
            if (event.getTimestamp() > thresholdNanos) {
                result.add(event);
            }
        }

        return result;
    }

    /**
     * Empties the buffer without returning events.
     */
    public void clear() {
        buffer.clear();
    }
}