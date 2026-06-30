# Nexus

eBPF-based Java SDK for real-time monitoring of Linux scheduler and cgroup state.

## Overview

Nexus tracks 6 kernel tracepoints (cgroup attach/release, sched_setattr, sched_setscheduler, setpriority, ioprio_set) and merges events with periodic `/proc` snapshots to provide a complete, up-to-date view of process scheduler attributes and cgroup associations.

## Quick start

```bash
# Build
./gradlew assembleDist

# Run
java -jar build/dist/nexus-java-1.0.0-all.jar config.yaml
```

## Features

- kernel tracepoints - stable API
- mmap and fast unsafe events reading
- procfs snapshots - full state baseline every N seconds
- custom callbacks for your own logic
- PERF_RECOR_LOST detection - knows when events are dropped
- cgroup filtering - track only processes in specified groups


## Configuration
Main properties:
```yaml
tracepoints:
  - "cgroup:cgroup_attach_task"
  - "cgroup:cgroup_release"
  - "raw:sys_enter"

snapshotIntervalMs: 5000
ringBuffer:
  dataPages: 16
```

## Observability

Built-in Prometheus metrics exposed on `:8080/metrics` for VictoriaMetrics/Prometheus scraping. Track event throughput, processing latency, ring buffer fill ratio, lost events, and snapshot duration to understand application load and health.
