package ebpf.nexus;
import ebpf.nexus.core.*;

public class EventsManager{
    private final ProgsLoader loader;
    private final EventsReader reader;


    public EventsManager(ProgsLoader loader,EventsReader reader, EventHandler handler){
        this.loader = loader;
        this.reader = reader;
        this.reader.setHandler(handler);
    }

    public void start(){
        loader.loadAll(); 
        reader.start();
    }

    // TODO:
    //public void stop() ???

}
