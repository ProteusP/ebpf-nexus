package ebpf.nexus;
import one.nio.os.bpf.*;
import ebpf.nexus.EventsManager;
import ebpf.nexus.readers.OneEventReader;
import ebpf.nexus.handlers.LoggingHandler;
import ebpf.nexus.loaders.OneEventLoader;
import java.util.List;
import java.util.ArrayList;

public class Main {
    int cpuCount;
    
    public static void main(String[] args) {
        
        String path = "/sys/fs/bpf/events";
        List<String> list = new ArrayList<>();
        list.add("cgroup_attach_task");
        

        EventsManager manager = new EventsManager(
            new OneEventLoader(list,path), new OneEventReader(path), new LoggingHandler()
        );

        manager.start();
    }

}
