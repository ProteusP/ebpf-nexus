package ebpf.nexus.model;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Event{
    public static final int SIZE  = 52;
    // обязательно дополнять отступом для выравнивания по 16!!!!!!! 
    public static final int PADDED_SIZE = 64; // тут можно формулой надо глянуть
    /// 8 без паддинга
    public long seq_num;
    public int cpu_id;
    public long timestamp;
    public int tp_id;
    public int pid;
    public long cgroup_id;
    public int nice_value;
    public int scheduler_policy;
    public int which_value;
    public int who_value;
    /// 

    public void readFromBytes(byte[] bytes, int eventOffset){
        ByteBuffer buffer = ByteBuffer.wrap(bytes, eventOffset, PADDED_SIZE);
        buffer.order(ByteOrder.nativeOrder());

        this.seq_num = buffer.getLong();
        this.cpu_id = buffer.getInt();
        this.timestamp = buffer.getLong();
        this.tp_id = buffer.getInt();
        this.pid = buffer.getInt();
        this.cgroup_id = buffer.getLong();
        this.nice_value = buffer.getInt();
        this.scheduler_policy = buffer.getInt();
        this.which_value = buffer.getInt();
        this.who_value = buffer.getInt();
    }

    @Override
    public String toString(){
        return String.format("Event{seq=%d, cpu_id=%d, timestamp=%d, tp_id=%d, pid=%d, cgroup_id=%d, nice_value=%d, scheduler_policy=%d, which_value=%d, who_value=%d}", seq_num,cpu_id, timestamp, tp_id, pid, cgroup_id, nice_value, scheduler_policy, which_value, who_value);
    }
    /* можно в будущем сделать интерфейс форматтера, чтобы 
    * отправлять в разные сервисы эвенты по разному
    */
}