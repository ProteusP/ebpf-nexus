package ebpf.nexus;
import one.nio.os.bpf.*;
import ebpf.nexus.EventsManager;
import ebpf.nexus.readers.OneEventReader;
import ebpf.nexus.handlers.LoggingHandler;
import ebpf.nexus.loaders.OneEventLoader;
import java.util.List;
import java.util.ArrayList;
import java.util.Scanner;

public class Main {
    int cpuCount;
    
    public static void main(String[] args) {
        
        List<String> tracepoints = new ArrayList<>();
        tracepoints.add("cgroup:cgroup_attach_task");
        tracepoints.add("syscalls:sys_enter_sched_setattr");

        try {
        
        OneEventLoader loader = new OneEventLoader(tracepoints);
        loader.loadAll();

        OneEventReader reader = new OneEventReader(loader.getProg(), "meta_map", "event_map");

        LoggingHandler handler = new LoggingHandler();

        reader.setHandler(handler);

        reader.start();

        Scanner scanner = new Scanner(System.in);
        scanner.nextLine();
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

}
