package ebpf.nexus.core;

public interface EventsReader{
    void start();
    void stop();
    void setHandler(EventHandler handler);
}