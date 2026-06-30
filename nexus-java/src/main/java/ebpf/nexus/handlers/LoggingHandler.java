package ebpf.nexus.handlers;

import ebpf.nexus.core.EventHandler;
import ebpf.nexus.core.StateChangeCallback;
import ebpf.nexus.model.Event;
import ebpf.nexus.model.ProcessInfo;
import ebpf.nexus.model.CgroupInfo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default handler that logs all events and state changes.
 * Implements both {@link EventHandler} for raw eBPF events
 * and {@link StateChangeCallback} for diff-based state updates.
 * <p>
 * Suitable for debugging and development.
 */
public class LoggingHandler implements EventHandler, StateChangeCallback {

    private static final Logger log = LoggerFactory.getLogger(LoggingHandler.class);

    @Override
    public void handle(Event event) {
        log.info("eBPF event received: {}", event);
    }

    @Override
    public void onProcessCreated(ProcessInfo process) {
        log.info("Process created: {}", process);
    }

    @Override
    public void onProcessChanged(ProcessInfo oldState, ProcessInfo newState) {
        log.info("Process changed: {} -> {}", oldState, newState);
    }

    @Override
    public void onProcessTerminated(int pid) {
        log.info("Process terminated: pid={}", pid);
    }

    @Override
    public void onCgroupChanged(CgroupInfo oldCgroup, CgroupInfo newCgroup) {
        log.info("Cgroup changed: {} -> {}", oldCgroup, newCgroup);
    }
}