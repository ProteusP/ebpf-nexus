package ebpf.nexus.model;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A point-in-time snapshot of the full system state.
 */
public class StateSnapshot {

    private long snapshotTimestamp;
    private Map<Integer, ProcessInfo> processes = new ConcurrentHashMap<>();
    private Map<Long, CgroupInfo> cgroups = new ConcurrentHashMap<>();

    public long getSnapshotTimestamp() { return snapshotTimestamp; }
    public void setSnapshotTimestamp(long snapshotTimestamp) { this.snapshotTimestamp = snapshotTimestamp; }

    public Map<Integer, ProcessInfo> getProcesses() { return processes; }
    public void setProcesses(Map<Integer, ProcessInfo> processes) { this.processes = processes; }

    public Map<Long, CgroupInfo> getCgroups() { return cgroups; }
    public void setCgroups(Map<Long, CgroupInfo> cgroups) { this.cgroups = cgroups; }
}