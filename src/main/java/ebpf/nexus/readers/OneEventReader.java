package ebpf.nexus.readers;
import ebpf.nexus.core.EventsReader;
import ebpf.nexus.core.EventHandler;
import ebpf.nexus.model.Event;
import java.io.IOException;
import one.nio.os.bpf.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class OneEventReader implements EventsReader{
    private static final int PRODUCED_KEY = 0;
    private static final int CONSUMED_KEY = 1;
    private static final int MAP_SIZE = 1024;
    private static final int KEY_MASK = MAP_SIZE - 1;
    private static final int LONG_SIZE = 8;
    private static final int POLL_INTERMAL_MS = 1000;

    private EventHandler handler;
    private volatile Boolean running;
    private BpfMap dataMap;
    private BpfMap metaMap;
    private BpfProg prog;
    private String metaMapName;
    private String dataMapName;
    
    private final byte[] producedKeyBytes;
    private final byte[] consumedKeyBytes;
    private ByteBuffer producedBuffer;
    private ByteBuffer consumedBuffer;
    private final int cpuCount;
    
    public OneEventReader(BpfProg prog, String metaMapName, String dataMapName) throws IOException{
        this.prog = prog;
        this.metaMapName = metaMapName;
        this.dataMapName = dataMapName;
        this.cpuCount = BpfMap.CPUS;

        this.producedKeyBytes = BpfMap.bytes(PRODUCED_KEY);
        this.consumedKeyBytes = BpfMap.bytes(CONSUMED_KEY);
        
        findMaps();
    }

    private void findMaps() throws IOException {
        int[] ids = prog.getMapIds();

        for (int id : ids){
            BpfMap map = BpfMap.getById(id);

            if (map.name.equals(dataMapName)){
                dataMap = map;
            }else if (map.name.equals(metaMapName)){
                metaMap = map;
            }
        }

        if (metaMap == null){
            throw new IOException("Meta map not found: " + metaMapName);
        }        

        if (dataMap == null){
            throw new IOException("Data map not found: " + dataMapName);
        }
    }

    private void initializeMaps() throws IOException {
        ByteBuffer initBuf = ByteBuffer.allocate(LONG_SIZE * cpuCount);
        initBuf.order(ByteOrder.nativeOrder());

        for (int cpu = 0; cpu < cpuCount; cpu++){
            initBuf.putLong(0);
        }

        byte[] initData = initBuf.array();

        metaMap.putIfAbsent(producedKeyBytes, initData);
        metaMap.putIfAbsent(consumedKeyBytes, initData);
    }

    private void processCycle() throws IOException {
        byte[] producedData = metaMap.get(producedKeyBytes);
        byte[] consumedData = metaMap.get(consumedKeyBytes);

        if (producedData == null || consumedData == null){
            return;
        }

        producedBuffer = ByteBuffer.wrap(producedData);
        consumedBuffer = ByteBuffer.wrap(consumedData);
        producedBuffer.order(ByteOrder.nativeOrder());
        consumedBuffer.order(ByteOrder.nativeOrder());


        boolean anyEventsProcessed = false;

        for (int cpu = 0; cpu < cpuCount; cpu++){
            anyEventsProcessed |= processCpu(cpu);
        }

        if (anyEventsProcessed){
            metaMap.put(consumedKeyBytes, consumedData); // consumedData обновится, тк сделан wrap
        }
    }

    private boolean processCpu(int cpu) throws IOException{
        int offset = cpu * LONG_SIZE;
        
        long produced = producedBuffer.getLong(offset);
        long consumed = consumedBuffer.getLong(offset);

        if (consumed >= produced){
            return false;
        }

        boolean processed = false;

        while (consumed < produced){
            if (processSingleEvent(cpu, consumed)){
                consumed++;
                processed = true;
            }else{
                consumed++; // Скипаем событие если оно не нашлось по ключу
            }
        }

         if (processed) {
            consumedBuffer.putLong(offset, consumed);
        }

        return processed;
    }

    private boolean processSingleEvent(int cpu, long slot) throws IOException {
        byte[] key = BpfMap.bytes((int)(slot & KEY_MASK));
        // по сути берем по модулю размера мапы, чтобы реализовать логику работы ringbuf

        byte[] eventData = dataMap.get(key);
        if (eventData == null){
            return false;
        }

        int eventOffset = cpu * Event.PADDED_SIZE;

        if (eventData.length < eventOffset + Event.PADDED_SIZE){
            return false; // вдруг данных почему то меньше приходит?
        }

        Event event = new Event();
        event.readFromBytes(eventData);
        handler.handle(event);

        return true;
    }

    @Override
    public void start(){
        try {
        running = true;
        initializeMaps();

        while (running){
            try {
                processCycle();
                Thread.sleep(POLL_INTERMAL_MS);
            }catch(InterruptedException e){
                Thread.currentThread().interrupt();
                break;
            }
        }
        } catch (Exception e){
            running = false;
            System.err.println("Error in event reader: " + e.getMessage());
            e.printStackTrace();
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