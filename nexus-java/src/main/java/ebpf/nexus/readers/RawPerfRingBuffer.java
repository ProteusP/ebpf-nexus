package ebpf.nexus.readers;

import one.nio.os.Mem;
import one.nio.os.perf.PerfCounter;

import java.io.Closeable;
import java.io.IOException;

import static one.nio.util.JavaInternals.unsafe;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Low-level reader for a single CPU's perf ring buffer.
 *
 * <p>Mmaps the perf counter's ring buffer directly into the process address
 * space and reads raw event data without extra copying or system calls.
 *
 * <p>Memory layout of the mmap region:
 * <pre>
 * Page 0:         metadata (perf_event_mmap_page)
 *   Offset 1024:  data_head - producer position, updated by kernel
 *   Offset 1032:  data_tail - consumer position, updated by userspace
 *   Offset 1040:  data_offset - where data area begins
 *   Offset 1048:  data_size - size of the data area
 * Pages 1..N:     ring buffer data (records of type perf_event_header)
 * </pre>
 *
 * <p>Records may wrap around the end of the data area. This reader handles
 * wrap-around correctly by copying in two chunks.
 *
 * <p>Thread-safety: a single consumer per ring buffer is assumed. The kernel
 * may write from any CPU (producer), but only one thread should update
 * {@code data_tail} (consumer).
 */
public class RawPerfRingBuffer implements Closeable {

    private static final int PAGE_SIZE = unsafe.pageSize();
    private static final Logger log = LoggerFactory.getLogger(RawPerfRingBuffer.class);

    /** Offsets in {@code perf_event_mmap_page}, stable across kernel versions. */
    private static final int DATA_HEAD_OFFSET = 1024;
    private static final int DATA_TAIL_OFFSET = 1032;
    private static final int DATA_OFFSET_OFFSET = 1040;
    private static final int DATA_SIZE_OFFSET = 1048;

    /** Record types in the ring buffer. */
    private static final int PERF_RECORD_LOST = 2;
    private static final int PERF_RECORD_SAMPLE = 9;

    /** Base address of the mmap region. */
    private final long address;

    /** Total mmap region size: (dataPages + 1) * PAGE_SIZE. */
    private final long totalSize;

    /** Offset from {@code address} to the start of the data area. */
    private final long dataOffset;

    /** Size of the data area in bytes. */
    private final long dataSize;

    /** Mask for wrapping positions within the ring buffer ({@code dataSize - 1}). */
    private final long mask;

    private final PerfCounter counter;

    private long totalLost = 0;

    public RawPerfRingBuffer(PerfCounter counter, int dataPages) throws IOException {
        this.counter = counter;
        this.totalSize = (dataPages + 1L) * PAGE_SIZE;

        // TODO: make 'counter.fd' public in one-nio
        this.address = Mem.mmap(
                0,
                totalSize,
                Mem.PROT_READ | Mem.PROT_WRITE,
                Mem.MAP_SHARED,
                counter.getFd(),
                0
        );

        if (address == -1) {
            throw new IOException("Failed to mmap perf counter");
        }

        this.dataOffset = unsafe.getLong(address + DATA_OFFSET_OFFSET);
        this.dataSize = unsafe.getLong(address + DATA_SIZE_OFFSET);
        this.mask = dataSize - 1;
        log.debug("Ring buffer ready: address={}, dataOffset={}, dataSize={}", address, dataOffset, dataSize);
    }

    /**
     * Reads the next raw event from the ring buffer into the provided buffer.
     *
     * @param buffer destination buffer for raw event data
     * @return number of bytes read, 0 if a non-sample record was skipped,
     *         -1 if no data is available
     */
    public int readRaw(byte[] buffer) {
        // Volatile read: producer (kernel) updates this from another CPU.
        long head = unsafe.getLongVolatile(null, address + DATA_HEAD_OFFSET);

        // Plain read: only this consumer updates tail.
        long tail = unsafe.getLong(address + DATA_TAIL_OFFSET);

        if (tail >= head) {
            return -1;
        }

        // Read header fields individually - they may wrap.
        int type = readIntFromRing(tail);
        int size = readShortFromRing(tail + 6) & 0xFFFF;

        if (size < 8) {
            unsafe.putLongVolatile(null, address + DATA_TAIL_OFFSET, tail + size);
            return 0;
        }

        // Handle lost events (ring buffer overflow)
        if (type == PERF_RECORD_LOST) {
            long lost = readLongFromRing(tail + 16);
            totalLost += lost;

            log.warn("Lost {} events (total {})", lost, totalLost);

            unsafe.putLongVolatile(null, address + DATA_TAIL_OFFSET, tail + size);
            return 0;
        }

        if (type != PERF_RECORD_SAMPLE) {
            unsafe.putLongVolatile(null, address + DATA_TAIL_OFFSET, tail + size);
            return 0;
        }

        // Data starts after 8-byte header + 4-byte raw_size = 12 bytes
        int dataLen = size - 12;

        if (dataLen > buffer.length) {
            // Buffer too small - skip the record to avoid stalling.
            unsafe.putLongVolatile(null, address + DATA_TAIL_OFFSET, tail + size);
            return -1;
        }

        // Copy raw data (after the 12-byte header), handling wrap-around.
        copyFromRing(tail + 12, buffer, 0, dataLen);

        // Release the record so the kernel can reuse the space.
        unsafe.putLongVolatile(null, address + DATA_TAIL_OFFSET, tail + size);

        return dataLen;
    }

    /**
     * Reads a single byte from a potentially wrapped offset.
     */
    private int readByteFromRing(long offset) {
        long pos = (offset & mask);
        return unsafe.getByte(address + dataOffset + pos) & 0xFF;
    }

    /**
     * Reads a 2-byte short from a potentially wrapped offset.
     */
    private int readShortFromRing(long offset) {
        long pos = (offset & mask);
        if (pos + 2 <= dataSize) {
            return unsafe.getShort(address + dataOffset + pos) & 0xFFFF;
        }
        // Wrapped: read in two bytes
        int first = readByteFromRing(offset) & 0xFF;
        int second = readByteFromRing(offset + 1) & 0xFF;
        return first | (second << 8);
    }

    /**
     * Reads a 4-byte integer from a potentially wrapped offset.
     */
    private int readIntFromRing(long offset) {
        long pos = (offset & mask);
        if (pos + 4 <= dataSize) {
            return unsafe.getInt(address + dataOffset + pos);
        }
        // Wrapped: read in four bytes
        int first = readByteFromRing(offset) & 0xFF;
        int second = readByteFromRing(offset + 1) & 0xFF;
        int third = readByteFromRing(offset + 2) & 0xFF;
        int fourth = readByteFromRing(offset + 3) & 0xFF;
        return first | (second << 8) | (third << 16) | (fourth << 24);
    }

    /**
     * Reads an 8-byte long from a potentially wrapped offset.
     */
    private long readLongFromRing(long offset) {
        long pos = (offset & mask);
        if (pos + 8 <= dataSize) {
            return unsafe.getLong(address + dataOffset + pos);
        }
        // Wrapped: read in two 4-byte parts
        long first = readIntFromRing(offset) & 0xFFFFFFFFL;
        long second = readIntFromRing(offset + 4) & 0xFFFFFFFFL;
        return first | (second << 32);
    }

    /**
     * Copies bytes from the ring buffer to a destination array,
     * handling wrap-around at the end of the data area.
     */
    private void copyFromRing(long offset, byte[] dest, int destOff, int len) {
        long startPos = dataOffset + (offset & mask);
        long end = address + dataOffset + dataSize;

        // First chunk: from startPos to end of data area (or len, whichever is smaller)
        int firstChunk = (int) Math.min(len, end - (address + startPos));
        for (int i = 0; i < firstChunk; i++) {
            dest[destOff + i] = unsafe.getByte(address + startPos + i);
        }

        // Second chunk: wrapped part from the beginning of the data area
        if (firstChunk < len) {
            long secondStart = address + dataOffset;
            for (int i = 0; i < len - firstChunk; i++) {
                dest[destOff + firstChunk + i] = unsafe.getByte(secondStart + i);
            }
        }
    }

    /**
     * Unmaps the ring buffer. After this call the {@code address} is invalid.
     */
    @Override
    public void close() {
        if (address != 0) {
            Mem.munmap(address, totalSize);
        }
    }
}