package ebpf.nexus.model;

import static one.nio.util.JavaInternals.unsafe;

/**
 * An event received from an eBPF tracepoint via the perf ring buffer.
 *
 * <p>Field layout must match the {@code struct event} defined in the eBPF program.
 * The struct is read from a local buffer that already contains a safe copy of the data;
 * no direct mmap access is performed here.
 *
 * <pre>{@code
 * struct event {
 *     u64 timestamp;          // offset  0  (8 bytes)
 *     u32 tracepointId;      // offset  8  (4 bytes)
 *     u32 cpuId;             // offset 12  (4 bytes)
 *     u32 pid;                // offset 16  (4 bytes)
 *     // 4 bytes padding      // offset 20
 *     u64 cgroupId;          // offset 24  (8 bytes)
 *     s32 niceValue;         // offset 32  (4 bytes)
 *     u32 schedulerPolicy;   // offset 36  (4 bytes)
 *     u32 whichValue;        // offset 40  (4 bytes)
 *     u32 whoValue;          // offset 44  (4 bytes)
 * };                          // total   48 bytes
 * }</pre>
 */
public class Event {

    /** Actual struct size from the eBPF program. */
    public static final int SIZE = 48;

    /** Size rounded up to the next 8-byte boundary for safe copying. */
    public static final int PADDED_SIZE = (SIZE + 7) & ~7; // 48

    // Offsets within the struct, matching the eBPF layout above.
    private static final int TIMESTAMP_OFFSET = 0;
    private static final int TRACEPOINT_ID_OFFSET = 8;
    private static final int CPU_ID_OFFSET = 12;
    private static final int PID_OFFSET = 16;
    private static final int CGROUP_ID_OFFSET = 24;
    private static final int NICE_VALUE_OFFSET = 32;
    private static final int SCHEDULER_POLICY_OFFSET = 36;
    private static final int WHICH_VALUE_OFFSET = 40;
    private static final int WHO_VALUE_OFFSET = 44;

    // Base offset of the first element in a byte[] for Unsafe access.
    private static final long BYTE_ARRAY_BASE = unsafe.arrayBaseOffset(byte[].class);


    private long timestamp;
    private int tracepointId;
    private int cpuId;
    private int pid;
    private long cgroupId;
    private int niceValue;
    private int schedulerPolicy;
    private int whichValue;
    private int whoValue;

    /**
     * Parses event fields from a local byte buffer using {@code Unsafe}.
     * No allocations - the offsets are resolved once as static constants.
     *
     * @param data   local buffer with raw event bytes
     * @param offset start offset in the buffer
     */
    public void readFromBytes(byte[] data, int offset) {
        long base = BYTE_ARRAY_BASE + offset;

        this.timestamp = unsafe.getLong(data, base + TIMESTAMP_OFFSET);
        this.tracepointId = unsafe.getInt(data, base + TRACEPOINT_ID_OFFSET);
        this.cpuId = unsafe.getInt(data, base + CPU_ID_OFFSET);
        this.pid = unsafe.getInt(data, base + PID_OFFSET);
        this.cgroupId = unsafe.getLong(data, base + CGROUP_ID_OFFSET);
        this.niceValue = unsafe.getInt(data, base + NICE_VALUE_OFFSET);
        this.schedulerPolicy = unsafe.getInt(data, base + SCHEDULER_POLICY_OFFSET);
        this.whichValue = unsafe.getInt(data, base + WHICH_VALUE_OFFSET);
        this.whoValue = unsafe.getInt(data, base + WHO_VALUE_OFFSET);
    }

    /**
     * Creates a deep copy of this event.
     *
     * <p>Required for safe deferred processing: when an event is placed in
     * {@link ebpf.nexus.state.EventBuffer}, the copy ensures that later
     * modifications to the original instance (or its reuse) do not corrupt
     * the buffered data.
     *
     * @return a new {@code Event} with identical field values
     */
    public Event copy() {
        Event copy = new Event();
        copy.timestamp = this.timestamp;
        copy.tracepointId = this.tracepointId;
        copy.cpuId = this.cpuId;
        copy.pid = this.pid;
        copy.cgroupId = this.cgroupId;
        copy.niceValue = this.niceValue;
        copy.schedulerPolicy = this.schedulerPolicy;
        copy.whichValue = this.whichValue;
        copy.whoValue = this.whoValue;
        return copy;
    }

    @Override
    public String toString() {
        return String.format(
                "Event{ts=%d, tp=%d, cpu=%d, pid=%d, cgroup=%d, nice=%d, policy=%d, which=%d, who=%d}",
                timestamp, tracepointId, cpuId, pid, cgroupId,
                niceValue, schedulerPolicy, whichValue, whoValue
        );
    }

    public long getTimestamp() {
        return timestamp;
    }

    public int getTpId() {
        return tracepointId;
    }

    public int getPid() {
        return pid;
    }

    public long getCgroupId() {
        return cgroupId;
    }

    public int getNiceValue() {
        return niceValue;
    }

    public int getSchedulerPolicy() {
        return schedulerPolicy;
    }

    public int getWhichValue() {
        return whichValue;
    }

    public int getWhoValue() {
        return whoValue;
    }
}