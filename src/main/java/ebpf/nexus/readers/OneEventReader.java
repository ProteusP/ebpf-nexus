package ebpf.nexus.readers;
import ebpf.nexus.core.EventsReader;
import ebpf.nexus.core.EventHandler;
import ebpf.nexus.model.Event;
import java.io.IOException;
import one.nio.os.bpf.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class OneEventReader implements EventsReader{
    private EventHandler handler;
    private Boolean running;
    private String mapPinPath;
    
    public OneEventReader(String mapPinPath){
        this.mapPinPath = mapPinPath;
    }

    @Override
    public void start(){
        try {
        running = true;

        byte[] key = BpfMap.bytes(0);

        BpfMap map = BpfMap.getPinned(mapPinPath);
        int cpuCount = BpfMap.CPUS;
        long[] timestamps = new long[cpuCount];
        for (int i = 0; i < cpuCount; i++){
            timestamps[i] = 0;
        }

        while (running){
            // Как то умнее бы ждать эвенты, чтобы не забивать всё проц время
         
            ByteBuffer eventsBuffer = ByteBuffer.wrap(map.get(key)).order(ByteOrder.nativeOrder());
            // получаем массив где лежат значения по ключу 0 для каждого ядра
            for (int cpu = 0; cpu < cpuCount; cpu++){
                byte[] eventBytes = new byte[Event.SIZE];

                eventsBuffer.get(eventBytes);

                Event event = new Event();
                event.readFromBytes(eventBytes);
                
                
                if (event.getTimestamp() > timestamps[cpu]){
                handler.handle(event);
                timestamps[cpu] = event.getTimestamp();
                }
            }
        }}
        catch(IOException e){
            running = false;
            System.out.println(e);
        }
    }

    @Override
    public void stop(){
        running = false;
    }

    @Override
    public void setHandler(EventHandler handler){
        this.handler = handler;
    }
}