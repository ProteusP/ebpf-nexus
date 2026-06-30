package ebpf.nexus;

import ebpf.nexus.config.Config;
import ebpf.nexus.loaders.PerfLoader;
import ebpf.nexus.readers.OneEventReader;
import ebpf.nexus.handlers.LoggingHandler;
import ebpf.nexus.state.ProcfsReader;
import ebpf.nexus.state.EventBuffer;
import ebpf.nexus.state.StateManager;
import ebpf.nexus.metrics.Metrics;

import java.util.Scanner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main entry point for the eBPF-based system state monitoring.
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) {
        // Parse command line arguments
        String configPath = "config.yaml";
        if (args.length > 0) {
            configPath = args[0];
        }

        try {
            // Load configuration
            Config config = Config.load(configPath);
            log.info("Configuration loaded from {}", configPath);

            // Apply logging level
            setLogLevel(config.getLogging().getLevel());

            // Phase 1: Load eBPF programs and create perf ring buffers
            PerfLoader loader = new PerfLoader(
                    config.getTracepoints(),
                    config.getBpfObjectDir(),
                    config.getRingBuffer().getDataPages(),
                    config.getTrackedCgroups()
            );
            loader.loadAll();

            if (loader.getRingBuffers() == null) {
                log.error("Failed to initialize ring buffers. Exiting.");
                System.exit(1);
            }

            // Phase 2: Create state management components
            ProcfsReader procfsReader = new ProcfsReader();
            EventBuffer eventBuffer = new EventBuffer();
            StateManager stateManager = new StateManager(procfsReader, eventBuffer);

            // Phase 3: Register user callbacks
            LoggingHandler loggingHandler = new LoggingHandler();
            stateManager.addCallback(loggingHandler);

            // Phase 4: Start eBPF event reader
            OneEventReader reader = new OneEventReader(loader.getRingBuffers());
            reader.setHandler(stateManager);

            int metricsPort = config.getMetricsPort();
            Metrics.start(metricsPort);
            log.info("Metrics server started on port {}", metricsPort);

            Thread readerThread = new Thread(reader::start, "ebpf-event-reader");
            readerThread.setDaemon(true);
            readerThread.start();

            // Phase 5: Start periodic snapshot cycle
            stateManager.start(config.getSnapshotIntervalMs());

            log.info("=== Nexus eBPF Monitor ===");
            log.info("Snapshot interval: {}ms", config.getSnapshotIntervalMs());
            log.info("Tracepoints: {}", config.getTracepoints());
            log.info("Press Enter to stop...");

            // Wait for user to stop
            Scanner scanner = new Scanner(System.in);
            scanner.nextLine();

            // Graceful shutdown
            log.info("Stopping...");
            stateManager.stop();
            reader.stop();
            Metrics.stop();
            readerThread.join(2000);
            loader.unloadAll();

            log.info("Stopped successfully.");

        } catch (Exception e) {
            log.error("Fatal error", e);
            System.exit(1);
        }
    }

    /**
     * Sets the SLF4J simple logger level at runtime.
     */
    private static void setLogLevel(String level) {
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", level.toLowerCase());
    }
}