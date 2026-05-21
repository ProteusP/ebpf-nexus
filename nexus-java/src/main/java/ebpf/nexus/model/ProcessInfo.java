package ebpf.nexus.model;

import java.util.Objects;

/**
 * Represents a process snapshot at a point in time.
 */
public class ProcessInfo {

    private int pid;
    private int ppid;
    private String comm;
    private int nice;
    private int schedulerPolicy;
    private long cgroupId;
    private int state;

    public int getPid() { return pid; }
    public void setPid(int pid) { this.pid = pid; }

    public int getPpid() { return ppid; }
    public void setPpid(int ppid) { this.ppid = ppid; }

    public String getComm() { return comm; }
    public void setComm(String comm) { this.comm = comm; }

    public int getNice() { return nice; }
    public void setNice(int nice) { this.nice = nice; }

    public int getSchedulerPolicy() { return schedulerPolicy; }
    public void setSchedulerPolicy(int schedulerPolicy) { this.schedulerPolicy = schedulerPolicy; }

    public long getCgroupId() { return cgroupId; }
    public void setCgroupId(long cgroupId) { this.cgroupId = cgroupId; }

    public int getState() { return state; }
    public void setState(int state) { this.state = state; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProcessInfo that = (ProcessInfo) o;
        return pid == that.pid;
    }

    @Override
    public int hashCode() {
        return Objects.hash(pid);
    }

    @Override
    public String toString() {
        return String.format("Process{pid=%d, ppid=%d, comm=%s, nice=%d, policy=%d, cgroup=%d}",
                pid, ppid, comm, nice, schedulerPolicy, cgroupId);
    }

    public boolean hasChangedFrom(ProcessInfo other) {
        if (other == null) return true;
        return this.ppid != other.ppid
                || !this.comm.equals(other.comm)
                || this.nice != other.nice
                || this.schedulerPolicy != other.schedulerPolicy
                || this.cgroupId != other.cgroupId
                || this.state != other.state;
    }
}