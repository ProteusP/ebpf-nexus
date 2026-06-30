package ebpf.nexus.metrics;

import io.prometheus.client.Counter;
import io.prometheus.client.Gauge;
import io.prometheus.client.Histogram;
import io.prometheus.client.hotspot.DefaultExports;
import io.prometheus.client.exporter.HTTPServer;

import java.io.IOException;

/**
 * Prometheus metrics exported for VictoriaMetrics scraping.
 */
public class Metrics {

    // Event counters by tracepoint type
    public static final Counter eventsTotal = Counter.build()
            .name("ebpf_events_total")
            .help("Total eBPF events received")
            .labelNames("tracepoint")
            .register();

    // Lost events counter
    public static final Counter eventsLostTotal = Counter.build()
            .name("ebpf_events_lost_total")
            .help("Total events lost due to ring buffer overflow")
            .register();

    // Tracked cgroups gauge
    public static final Gauge trackedCgroups = Gauge.build()
            .name("ebpf_tracked_cgroups")
            .help("Number of tracked cgroups")
            .register();

    // Ring buffer fill ratio
    public static final Gauge ringBufferFillRatio = Gauge.build()
        .name("ebpf_ringbuffer_fill_ratio")
        .help("Ring buffer fill ratio across all CPUs (0.0-1.0)")
        .register();

    // Processing latency histogram
    public static final Histogram processingLatency = Histogram.build()
            .name("ebpf_processing_latency_seconds")
            .help("Event processing latency in seconds")
            .buckets(0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1)
            .register();

    // Snapshot duration histogram
    public static final Histogram snapshotDuration = Histogram.build()
            .name("ebpf_snapshot_duration_seconds")
            .help("Full /proc snapshot duration in seconds")
            .register();

    // Number of processes in snapshot
    public static final Gauge snapshotProcesses = Gauge.build()
            .name("ebpf_snapshot_processes_total")
            .help("Number of processes in the last snapshot")
            .register();

    // State changes by type
    public static final Counter stateChangesTotal = Counter.build()
            .name("ebpf_state_changes_total")
            .help("Total state changes detected")
            .labelNames("type") // created, changed, terminated
            .register();

    private static HTTPServer server;

    /**
     * Starts the HTTP metrics server on the given port.
     * VictoriaMetrics scrapes from this endpoint.
     */
    public static void start(int port) throws IOException {
        DefaultExports.initialize();
        server = new HTTPServer(port);
    }

    /**
     * Stops the metrics server.
     */
    public static void stop() {
        if (server != null) {
            server.stop();
        }
    }
}