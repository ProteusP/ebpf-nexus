package ebpf.nexus;
import ebpf.nexus.core.*;

public class EventsManager{
    private final ProgsLoader loader;
    private final EventsReader reader;
    private final EventHandler handler;


    public EventsManager(ProgsLoader loader,EventsReader reader, EventHandler handler){
        this.loader = loader;
        this.reader = reader;
        this.handler = handler;
        this.reader.setHandler(this.handler);
    }

    public void start(){
        loader.loadAll(); 
        reader.start();
    }

    //public void stop() ???

}
