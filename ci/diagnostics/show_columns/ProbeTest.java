import io.questdb.griffin.engine.table.ShowColumnsProbe;

/** Isolated observer test: injected delay is never included in the CI overlay. */
public class ProbeTest {
    public static void main(String[] args) throws Exception {
        var fast = ShowColumnsProbe.begin("fast");
        fast.stage("cursor-ready");
        fast.finish("cursor-close");
        var slow = ShowColumnsProbe.begin("injected-test-only");
        slow.stage("metadata-read-lock-wait");
        Thread.sleep(6200);
        slow.finish("open-error:Injected");
        Thread.sleep(300);
    }
}
