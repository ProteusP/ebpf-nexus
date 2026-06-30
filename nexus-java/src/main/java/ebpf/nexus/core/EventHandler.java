package ebpf.nexus.core;
import ebpf.nexus.model.Event;
public interface EventHandler{
    void handle(Event event);
}