package ebpf.nexus.state;

import ebpf.nexus.core.EventHandler;
import ebpf.nexus.core.StateChangeCallback;
import ebpf.nexus.model.Event;
import ebpf.nexus.model.StateSnapshot;
import ebpf.nexus.model.ProcessInfo;
import ebpf.nexus.model.CgroupInfo;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates full system snapshots from {@code /proc} with incremental eBPF events.
 *
 * <p>On a fixed interval the manager:
 * <ol>
 *   <li>Reads the complete process and cgroup state from procfs.</li>
 *   <li>Drains eBPF events that were buffered while the snapshot was in progress.</li>
 *   <li>Applies the buffered events to the fresh snapshot, bringing it up to date.</li>
 *   <li>Compares the new snapshot with the previous one and notifies
 *       {@link StateChangeCallback}s only for entities that actually changed.</li>
 * </ol>
 *
 * <p>Events arriving between snapshots are applied to the in-memory state immediately.
 */
public class StateManager implements EventHandler {

    private static final Logger log = LoggerFactory.getLogger(StateManager.class);

    private final ProcfsReader procfsReader;
    private final EventBuffer eventBuffer;
    private final List<StateChangeCallback> callbacks = new CopyOnWriteArrayList<>();

    private final AtomicBoolean isSnapshotInProgress = new AtomicBoolean(false);

    private StateSnapshot currentState;
    private long lastSnapshotEndTime;

    private ScheduledExecutorService scheduler;

    public StateManager(ProcfsReader procfsReader, EventBuffer eventBuffer) {
        this.procfsReader = procfsReader;
        this.eventBuffer = eventBuffer;
    }

    public void addCallback(StateChangeCallback callback) {
        callbacks.add(callback);
    }

    public void removeCallback(StateChangeCallback callback) {
        callbacks.remove(callback);
    }

    /**
     * Starts the periodic snapshot cycle.
     *
     * @param intervalMs interval between full state reads, in milliseconds
     */
    public void start(long intervalMs) {
        lastSnapshotEndTime = System.currentTimeMillis();
        scheduler = Executors.newScheduledThreadPool(1);

        scheduler.scheduleAtFixedRate(
                this::doSnapshotCycle,
                0, intervalMs, TimeUnit.MILLISECONDS
        );

        log.info("State manager started, interval={}ms", intervalMs);
    }

    /**
     * Called by the eBPF event reader for every incoming event.
     *
     * <p>If a snapshot is currently in progress the event is buffered and applied later.
     * Otherwise, it is applied to the live state immediately.
     */
    @Override
    public void handle(Event event) {
        if (isSnapshotInProgress.get()) {
            eventBuffer.addEvent(event.copy());
        } else {
            applyEventToCurrentState(event);
        }
    }

    private void doSnapshotCycle() {
        if (!isSnapshotInProgress.compareAndSet(false, true)) {
            log.warn("Previous snapshot still in progress, skipping this cycle");
            return;
        }

        eventBuffer.startBuffering();

        try {
            StateSnapshot freshSnapshot = procfsReader.readFullState();
            log.info("Snapshot completed, {} processes", freshSnapshot.processes.size());

            List<Event> bufferedEvents = eventBuffer.drain(lastSnapshotEndTime);
            log.info("Applying {} buffered events to snapshot", bufferedEvents.size());

            for (Event event : bufferedEvents) {
                applyEventToSnapshot(freshSnapshot, event);
            }

            if (currentState != null) {
                diffAndNotify(currentState, freshSnapshot);
            } else {
                for (ProcessInfo p : freshSnapshot.processes.values()) {
                    notifyProcessCreated(p);
                }
            }

            currentState = freshSnapshot;
            lastSnapshotEndTime = System.currentTimeMillis();

        } catch (IOException e) {
            log.error("Error during snapshot cycle", e);
        } finally {
            isSnapshotInProgress.set(false);
        }
    }

    private void applyEventToCurrentState(Event event) {
        if (currentState == null) return;
        applyEventToSnapshot(currentState, event);
    }


    /**
     * Applies a single eBPF event to a snapshot, mutating the relevant entity in place.
     *
     * <p>TODO: consider a registry of event handlers instead of a switch
     * to make adding new tracepoint types easier.
     */
    private void applyEventToSnapshot(StateSnapshot snapshot, Event event) {
        switch (event.getTpId()) {
            case 0: // TP_SCHED_SETATTR
                ProcessInfo proc0 = snapshot.processes.get(event.getPid());
                if (proc0 != null) {
                    proc0.nice = event.getNiceValue();
                    proc0.schedulerPolicy = event.getSchedulerPolicy();
                }
                break;

            case 1: // TP_SCHED_SETSCHEDULER
                ProcessInfo proc1 = snapshot.processes.get(event.getPid());
                if (proc1 != null) {
                    proc1.schedulerPolicy = event.getSchedulerPolicy();
                }
                break;

            case 2: // TP_SETPRIORITY
                // which_value: PRIO_PROCESS=0, PRIO_PGRP=1, PRIO_USER=2
                if (event.getWhichValue() == 0) { // PRIO_PROCESS - affects single pid
                    ProcessInfo proc2 = snapshot.processes.get(event.getWhoValue());
                    if (proc2 != null) {
                        proc2.nice = event.getNiceValue();
                    }
                }
                // PRIO_PGRP and PRIO_USER require iterating all processes
                // to find matching pgid/uid - deferred to next procfs snapshot
                break;

            case 3: // TP_IOPRIO_SET
                // I/O priority change - not yet tracked in ProcessInfo
                break;

            case 4: // TP_CGROUP_ATTACH_TASK
                ProcessInfo proc4 = snapshot.processes.get(event.getPid());
                if (proc4 != null) {
                    proc4.cgroupId = event.getCgroupId();
                }
                break;

            case 5: // TP_CGROUP_RELEASE
                // Cgroup released - no pid, just cgroup_id
                // Could invalidate cgroup cache or notify about cgroup removal
                break;

            default:
                log.debug("Unknown tracepoint id: {}", event.getTpId());
        }
    }

    /**
     * Compares two snapshots and notifies callbacks for detected changes.
     */
    private void diffAndNotify(StateSnapshot oldState, StateSnapshot newState) {
        for (ProcessInfo newProc : newState.processes.values()) {
            ProcessInfo oldProc = oldState.processes.get(newProc.pid);

            if (oldProc == null) {
                notifyProcessCreated(newProc);
            } else if (newProc.hasChangedFrom(oldProc)) {
                notifyProcessChanged(oldProc, newProc);
            }
        }

        for (int oldPid : oldState.processes.keySet()) {
            if (!newState.processes.containsKey(oldPid)) {
                notifyProcessTerminated(oldPid);
            }
        }

        for (CgroupInfo newCgroup : newState.cgroups.values()) {
            CgroupInfo oldCgroup = oldState.cgroups.get(newCgroup.getId());

            if (oldCgroup == null) {
                // onCgroupCreated(newCgroup) - not yet implemented
            } else if (newCgroup.hasChangedFrom(oldCgroup)) {
                notifyCgroupChanged(oldCgroup, newCgroup);
            }
        }
    }

    private void notifyProcessCreated(ProcessInfo process) {
        for (StateChangeCallback callback : callbacks) {
            try {
                callback.onProcessCreated(process);
            } catch (Exception e) {
                log.error("Callback error in onProcessCreated", e);
            }
        }
    }

    private void notifyProcessChanged(ProcessInfo oldState, ProcessInfo newState) {
        for (StateChangeCallback callback : callbacks) {
            try {
                callback.onProcessChanged(oldState, newState);
            } catch (Exception e) {
                log.error("Callback error in onProcessChanged", e);
            }
        }
    }

    private void notifyProcessTerminated(int pid) {
        for (StateChangeCallback callback : callbacks) {
            try {
                callback.onProcessTerminated(pid);
            } catch (Exception e) {
                log.error("Callback error in onProcessTerminated", e);
            }
        }
    }

    private void notifyCgroupChanged(CgroupInfo oldCgroup, CgroupInfo newCgroup) {
        for (StateChangeCallback callback : callbacks) {
            try {
                callback.onCgroupChanged(oldCgroup, newCgroup);
            } catch (Exception e) {
                log.error("Callback error in onCgroupChanged", e);
            }
        }
    }

    public void stop() {
        if (scheduler != null) {
            scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
            }
        }
    }
}