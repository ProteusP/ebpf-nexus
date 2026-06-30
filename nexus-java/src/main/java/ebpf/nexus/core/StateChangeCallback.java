package ebpf.nexus.core;

import ebpf.nexus.model.ProcessInfo;
import ebpf.nexus.model.CgroupInfo;

public interface StateChangeCallback {
    void onProcessCreated(ProcessInfo process);
    void onProcessChanged(ProcessInfo oldState, ProcessInfo newState);
    void onProcessTerminated(int pid);
    void onCgroupChanged(CgroupInfo oldCgroup, CgroupInfo newCgroup);
}