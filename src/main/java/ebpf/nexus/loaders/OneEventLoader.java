package ebpf.nexus.loaders;
import ebpf.nexus.core.ProgsLoader;
import one.nio.os.bpf.*;
import one.nio.os.perf.*;
import java.nio.file.Files;
import java.nio.file.Paths;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class OneEventLoader implements ProgsLoader{

    private BpfProg prog;
    private List<String> tracepoints;
    private List<PerfCounter> perfCounters = new ArrayList<>();

    public OneEventLoader(List<String> tracepoints){
        this.tracepoints = tracepoints;
    }

    public BpfProg getProg(){
        return prog;
    }

    @Override
    public void loadAll() {
        try {

            this.prog = BpfProg.load("tracepoints.o", ProgType.TRACEPOINT);

            for (String tracepoint : tracepoints){
                attachTracepoint(tracepoint);
            }

            System.out.println("Все трейспоинты загружены");

        } catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    //TODO:
    public void unloadAll(){
        System.out.println("UNLOAD");
    }

    private void attachTracepoint(String tracepointName) throws IOException {
        
        String[] parts = tracepointName.split(":");
        String category = parts[0];
        String name = parts[1];

        String path = "/sys/kernel/debug/tracing/events/" + category + "/" + name + "/id";
        String idStr = Files.readString(Paths.get(path)).trim();
        
        int tpId = Integer.parseInt(idStr);
        
        PerfEvent event = PerfEvent.tracepoint(tpId);
        
        PerfCounter leader = Perf.openGlobal(
        event,
        Perf.ANY_PID
    );
        perfCounters.add(leader);
        int cpuCount = Runtime.getRuntime().availableProcessors();

        prog.attach(leader);
        System.out.println(String.format("%s attached", tracepointName));
    }
}