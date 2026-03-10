package ebpf.nexus.loaders;
import ebpf.nexus.core.ProgsLoader;
import one.nio.os.bpf.*;
import java.io.IOException;
import java.util.List;

public class OneEventLoader implements ProgsLoader{

    private BpfProg prog;
    private Handle handle;
    private String mapPinPath;
    private List<String> tracepoints;

    public OneEventLoader(List<String> tracepoints, String mapPinPath){
        this.mapPinPath = mapPinPath;
        this.tracepoints = tracepoints;
    }

    @Override
    public void loadAll() {
        try {
            /* пока пусть грузит так, потом на каждый тип загрузчика стоит сделать разные bpf проги
            * так как интерфейсы передачи событий могут быть разными
            * и соотв. нужны разные мапы
            */
            this.prog = BpfProg.load("events.o", ProgType.RAW_TRACEPOINT);

            for (String tracepoint : tracepoints){
                System.out.println(String.format("Устанавливаю %s",tracepoint));
                this.handle = prog.attachRawTracepoint(tracepoint);
                System.out.println(String.format("Установлен %s",tracepoint));
            }
            int ids[] = prog.getMapIds();
            int mapId = ids[0]; // по хорошему кофигурировать название мапы и искать её тут но пока пусть так

            BpfMap map = BpfMap.getById(mapId);

            map.pin(mapPinPath);
        } catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    public void unloadAll(){
        handle.close();
        prog.close();
    }
}