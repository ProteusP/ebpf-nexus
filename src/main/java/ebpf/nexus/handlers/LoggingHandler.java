package ebpf.nexus.handlers;

import ebpf.nexus.core.EventHandler;
import ebpf.nexus.model.Event;

public class LoggingHandler implements EventHandler{
    @Override
    public void handle(Event event){
        System.out.println(event.toString());
    }
}