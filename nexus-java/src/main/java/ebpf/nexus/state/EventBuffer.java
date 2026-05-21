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

    /**
     * Clears the buffer and records the start time of a new snapshot cycle.
     * Events with timestamps before this point will be filtered out.
     */
    public void startBuffering() {
        bufferStartTime = System.currentTimeMillis();
        buffer.clear();
    }

    /**
     * Adds an event to the buffer. Thread-safe.
     */
    public void addEvent(Event event) {
        buffer.add(event);
    }

    /**
     * Drains all events with a timestamp greater than the given threshold.
     *
     * @param sinceTimestamp keep only events newer than this
     * @return list of matching events in insertion order
     */
    public List<Event> drain(long sinceTimestamp) {
        List<Event> result = new ArrayList<>();

        for (Event event : buffer) {
            if (event.getTimestamp() > sinceTimestamp) {
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