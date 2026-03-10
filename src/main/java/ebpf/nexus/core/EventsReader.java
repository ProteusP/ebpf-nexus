package ebpf.nexus.core;

import one.nio.os.bpf.*;

public interface EventsReader{
    void start();
    void stop();
    void setHandler(EventHandler handler);
}