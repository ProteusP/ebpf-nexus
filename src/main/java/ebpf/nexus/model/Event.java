package ebpf.nexus.model;

import java.nio.ByteBuffer;

public class Event{

    public static final int SIZE = 12;
    private long timestamp;
    private int pid;
    // и другие...

    public void readFromBytes(byte[] bytes){
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        this.timestamp = buffer.getLong();
        this.pid = buffer.getInt(8);
    }

    @Override
    public String toString(){
        return String.format("Event{timestamp=%d, pid=%d}", timestamp, pid);
    }
    /* можно в будущем сделать интерфейс форматтера, чтобы 
    * отправлять в разные сервисы эвенты по разному
    */
   public long getTimestamp(){
    return timestamp;
   }
}