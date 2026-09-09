package io.questdb.griffin.engine.table;

import java.io.BufferedWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Investigation-only module overlay. Query threads never write diagnostic files. */
public final class ShowColumnsProbe {
    private static final ConcurrentHashMap<Long, ShowColumnsProbe> ACTIVE = new ConcurrentHashMap<>();
    private static final ConcurrentLinkedQueue<String> EVENTS = new ConcurrentLinkedQueue<>();
    private static final AtomicInteger QUEUED = new AtomicInteger();
    private static final AtomicLong DROPPED = new AtomicLong();
    private static final AtomicLong IDS = new AtomicLong();
    private static final long SLOW_NS = 5_000_000_000L;
    private static final Path DIRECTORY = Path.of(System.getProperty("qwp.show.columns.dir"));
    private final long id = IDS.incrementAndGet();
    private final long started = System.nanoTime();
    private final String table;
    private volatile String stage;
    private volatile long threadId;
    private volatile String threadName;
    private volatile boolean finished;

    static {
        Thread observer = new Thread(ShowColumnsProbe::observe, "show-columns-observer");
        observer.setDaemon(true);
        observer.start();
    }

    private ShowColumnsProbe(CharSequence table) {
        this.table = table.toString().replace('\t', ' ').replace('\n', ' ').replace('\r', ' ');
        stage("cursor-enter");
        ACTIVE.put(id, this);
    }

    public static ShowColumnsProbe begin(CharSequence table) {
        return new ShowColumnsProbe(table);
    }

    public void stage(String next) {
        if (next.equals(stage) && threadId == Thread.currentThread().threadId()) return;
        threadId = Thread.currentThread().threadId();
        threadName = Thread.currentThread().getName();
        stage = next;
        enqueue(line(next));
    }

    public void finish(String reason) {
        if (!finished) {
            finished = true;
            stage(reason);
            ACTIVE.remove(id);
        }
    }

    private String line(String event) {
        return System.currentTimeMillis() + "\t" + System.nanoTime() + "\t" + id
                + "\t" + threadId + "\t" + threadName + "\t" + table + "\t" + event
                + "\t" + (System.nanoTime() - started);
    }

    private static void enqueue(String line) {
        if (QUEUED.incrementAndGet() <= 8192) {
            EVENTS.offer(line);
        } else {
            QUEUED.decrementAndGet();
            DROPPED.incrementAndGet();
        }
    }

    private static void observe() {
        boolean captured = false;
        long heartbeat = 0;
        try (BufferedWriter out = Files.newBufferedWriter(DIRECTORY.resolve("show-columns.tsv"))) {
            out.write("wall_ms\tnano_time\tquery_id\tjava_thread_id\tthread\ttable\tstage\telapsed_ns\n");
            while (true) {
                String event;
                while ((event = EVENTS.poll()) != null) {
                    QUEUED.decrementAndGet();
                    out.write(event);
                    out.newLine();
                }
                long now = System.nanoTime();
                if (now - heartbeat >= 1_000_000_000L) {
                    heartbeat = now;
                    out.write(System.currentTimeMillis() + "\t" + now + "\t0\t0\tobserver\t-\theartbeat dropped=" + DROPPED.get() + "\t0\n");
                    for (ShowColumnsProbe probe : ACTIVE.values()) {
                        out.write(probe.line("active:" + probe.stage));
                        out.newLine();
                        if (!captured && !probe.finished && now - probe.started >= SLOW_NS) {
                            // Persist the stage before asking the external watchdog for stacks.
                            out.flush();
                            Files.writeString(DIRECTORY.resolve("show-columns-slow"), probe.line("slow:" + probe.stage) + "\n");
                            captured = true;
                        }
                    }
                }
                out.flush();
                Thread.sleep(100);
            }
        } catch (Throwable error) {
            error.printStackTrace();
            try {
                Files.writeString(DIRECTORY.resolve("show-columns-error"), error.toString());
            } catch (Throwable ignored) {
                // The harness also checks telemetry presence and completion.
            }
        }
    }
}
