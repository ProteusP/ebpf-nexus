package ebpf.nexus.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.ArrayList;

/**
 * Application configuration loaded from a YAML file.
 */
public class Config {

    private List<String> tracepoints;
    private long snapshotIntervalMs;
    private RingBufferConfig ringBuffer;
    private String bpfObjectDir;
    private LoggingConfig logging;
    private List<Long> trackedCgroups = new ArrayList<>();
    private int metricsPort = 8080;

    public List<String> getTracepoints() { return tracepoints; }
    public long getSnapshotIntervalMs() { return snapshotIntervalMs; }
    public RingBufferConfig getRingBuffer() { return ringBuffer; }
    public String getBpfObjectDir() { return bpfObjectDir; }
    public LoggingConfig getLogging() { return logging; }

    public void setTracepoints(List<String> tracepoints) { this.tracepoints = tracepoints; }
    public void setSnapshotIntervalMs(long snapshotIntervalMs) { this.snapshotIntervalMs = snapshotIntervalMs; }
    public void setRingBuffer(RingBufferConfig ringBuffer) { this.ringBuffer = ringBuffer; }
    public void setBpfObjectDir(String bpfObjectDir) { this.bpfObjectDir = bpfObjectDir; }
    public void setLogging(LoggingConfig logging) { this.logging = logging; }
    public List<Long> getTrackedCgroups() { return trackedCgroups; }
    public void setTrackedCgroups(List<Long> trackedCgroups) { this.trackedCgroups = trackedCgroups; }
    public int getMetricsPort() { return metricsPort; }
    public void setMetricsPort(int metricsPort) { this.metricsPort = metricsPort; }

    /**
     * Loads configuration from a YAML file.
     *
     * @param path path to the YAML configuration file
     * @return parsed and validated configuration
     * @throws IOException if the file cannot be read or parsed
     * @throws IllegalArgumentException if required fields are missing or invalid
     */
    public static Config load(String path) throws IOException {
        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Config config;

        // Try external file first, then classpath resource
        File file = new File(path);
        if (file.exists()) {
            config = mapper.readValue(file, Config.class);
        } else {
            InputStream resource = Config.class.getClassLoader()
                    .getResourceAsStream(path);
            if (resource == null) {
                // Fall back to default config
                resource = Config.class.getClassLoader()
                        .getResourceAsStream("config.yaml");
            }
            if (resource == null) {
                throw new IOException("Configuration not found: " + path);
            }
            config = mapper.readValue(resource, Config.class);
        }

        config.validate();
        return config;
    }

    /**
     * Validates the configuration and applies defaults.
     */
    private void validate() {
        if (tracepoints == null || tracepoints.isEmpty()) {
            throw new IllegalArgumentException("tracepoints must not be empty");
        }
        if (snapshotIntervalMs <= 0) {
            snapshotIntervalMs = 5000; // Default 5 seconds
        }
        if (ringBuffer == null) {
            ringBuffer = new RingBufferConfig();
        }
        if (ringBuffer.getDataPages() <= 0) {
            ringBuffer.setDataPages(16);
        }
        if (bpfObjectDir == null || bpfObjectDir.isEmpty()) {
            bpfObjectDir = "build/dist/ebpf";
        }
        if (logging == null) {
            logging = new LoggingConfig();
        }
        if (logging.getLevel() == null || logging.getLevel().isEmpty()) {
            logging.setLevel("INFO");
        }
    }

    /**
     * Ring buffer configuration.
     */
    public static class RingBufferConfig {
        private int dataPages = 16;

        public int getDataPages() { return dataPages; }
        public void setDataPages(int dataPages) { this.dataPages = dataPages; }
    }

    /**
     * Logging configuration.
     */
    public static class LoggingConfig {
        private String level = "INFO";

        public String getLevel() { return level; }
        public void setLevel(String level) { this.level = level; }
    }
}