package ebpf.nexus.loaders;
import ebpf.nexus.core.ProgsLoader;
import one.nio.os.bpf.*;
import one.nio.os.perf.*;

import java.io.IOException;
import java.util.List;

public class OneEventLoader implements ProgsLoader{

    private BpfProg rawTpProg;
    private BpfProg syscallsProg;
    private Handle handle;
    private List<String> tracepoints;
    private List<String> syscalls;

    public OneEventLoader(List<String> tracepoints, List<String> syscalls){
        this.syscalls = syscalls;
        this.tracepoints = tracepoints;
    }

    @Override
    public void loadAll() {
        try {

            this.rawTpProg = BpfProg.load("raw_tracepoints.o", ProgType.RAW_TRACEPOINT);
            this.syscallsProg = BpfProg.load("syscalls.o", ProgType.TRACEPOINT);

            for (String tracepoint : tracepoints){
                this.handle = rawTpProg.attachRawTracepoint(tracepoint);
            }

            System.out.println("Все трейспоинты загружены");

            // TODO:
            for (String syscall : syscalls){
                attachSyscallTracepoint(syscallsProg, syscall);
            }

            System.out.println("Все сисколлы загружены");

        } catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    //TODO
    public void unloadAll(){
        handle.close();

    }

    private void attachSyscallTracepoint(BpfProg prog, String tracepointName) throws IOException {

        PerfEvent event = PerfEvent.tracepoint(tracepointName);

        PerfCounterGlobal counter = Perf.openGlobal(event,Perf.ANY_PID, PerfOption.period(1));

        prog.attach(counter);
    }

}