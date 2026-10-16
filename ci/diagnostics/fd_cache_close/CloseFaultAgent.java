package diagnostic;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

/** Local, Linux-only fault injection. No server sources or binaries are modified. */
public final class CloseFaultAgent {
    private static final AtomicBoolean FIRED = new AtomicBoolean();
    private static Path directory;
    private static String mode;
    private static long delayMillis;

    public static void premain(String arguments, Instrumentation instrumentation) throws Exception {
        directory = Path.of(arguments);
        mode = Files.readString(directory.resolve("mode")).trim();
        delayMillis = Long.parseLong(Files.readString(directory.resolve("delay-ms")).trim());
        if (!Arrays.asList("baseline", "outside", "inside").contains(mode) || delayMillis < 0 || delayMillis > 15000) {
            throw new IllegalArgumentException("Invalid diagnostic mode/delay");
        }
        instrumentation.addTransformer(new Transformer());
    }

    public static void beforeClose(int osFd, boolean inside) {
        if (osFd <= 2 || FIRED.get() || inside != mode.equals("inside")
                || !Thread.currentThread().getName().startsWith("shared-write_")
                || !Files.exists(directory.resolve("arm"))) {
            return;
        }
        try {
            String path = Files.readSymbolicLink(Path.of("/proc/self/fd/" + osFd)).toString();
            if (!path.startsWith(directory.resolve("data/db/fault_o3~").toString())
                    || Arrays.stream(Thread.currentThread().getStackTrace())
                    .noneMatch(frame -> frame.getClassName().equals("io.questdb.cairo.O3Utils"))) {
                return;
            }
            if (!FIRED.compareAndSet(false, true)) {
                return;
            }
            var field = Class.forName("io.questdb.std.Files").getDeclaredField("fdCache");
            field.setAccessible(true);
            boolean held = Thread.holdsLock(field.get(null));
            if (held != inside) {
                throw new IllegalStateException("Unexpected FdCache ownership: " + held);
            }
            String details = "mode=" + mode + "\nthread=" + Thread.currentThread().getName()
                    + "\nfd=" + osFd + "\npath=" + path + "\nmonitorHeld=" + held
                    + "\nepochMs=" + System.currentTimeMillis() + "\nnanoTime=" + System.nanoTime()
                    + "\n" + Arrays.toString(Thread.currentThread().getStackTrace()) + "\n";
            Files.writeString(directory.resolve("fault-start"), details);
            long start = System.nanoTime();
            if (!mode.equals("baseline")) {
                Thread.sleep(delayMillis);
            }
            Files.writeString(directory.resolve("fault-end"),
                    "epochMs=" + System.currentTimeMillis() + "\nheldMs=" + (System.nanoTime() - start) / 1e6 + "\n");
        } catch (Throwable error) {
            error.printStackTrace();
            try {
                Files.writeString(directory.resolve("fault-error"), error.toString());
            } catch (Exception ignored) {
                // The harness also rejects a missing fault-end marker.
            }
        }
    }

    private static final class Transformer implements ClassFileTransformer {
        @Override
        public byte[] transform(ClassLoader loader, String name, Class<?> redefining,
                                ProtectionDomain domain, byte[] bytes) {
            boolean cache = name.equals("io/questdb/std/FdCache");
            boolean o3 = name.equals("io/questdb/cairo/O3Utils");
            if (!cache && !o3) {
                return null;
            }
            ClassReader reader = new ClassReader(bytes);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            int[] injections = {0};
            reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String method, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor delegate = super.visitMethod(access, method, descriptor, signature, exceptions);
                    boolean cacheClose = cache && method.equals("close") && descriptor.equals("(J)I");
                    boolean o3Close = o3 && method.equals("close")
                            && descriptor.equals("(Lio/questdb/std/FilesFacade;J)V");
                    if (!cacheClose && !o3Close) {
                        return delegate;
                    }
                    return new MethodVisitor(Opcodes.ASM9, delegate) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            if (o3Close) {
                                // The high 32 bits of QuestDB's unique fd contain the OS fd.
                                super.visitVarInsn(Opcodes.LLOAD, 1);
                                super.visitIntInsn(Opcodes.BIPUSH, 32);
                                super.visitInsn(Opcodes.LUSHR);
                                super.visitInsn(Opcodes.L2I);
                                super.visitInsn(Opcodes.ICONST_0);
                                hook();
                            }
                        }

                        @Override
                        public void visitMethodInsn(int opcode, String owner, String method,
                                                    String desc, boolean isInterface) {
                            if (cacheClose && opcode == Opcodes.INVOKESTATIC
                                    && owner.equals("io/questdb/std/Files")
                                    && method.equals("close0") && desc.equals("(I)I")) {
                                // Preserve the native call's fd argument; the synchronized method's monitor is held.
                                super.visitInsn(Opcodes.DUP);
                                super.visitInsn(Opcodes.ICONST_1);
                                hook();
                            }
                            super.visitMethodInsn(opcode, owner, method, desc, isInterface);
                        }

                        private void hook() {
                            super.visitMethodInsn(Opcodes.INVOKESTATIC, "diagnostic/CloseFaultAgent",
                                    "beforeClose", "(IZ)V", false);
                            injections[0]++;
                        }
                    };
                }
            }, 0);
            try {
                Files.writeString(directory.resolve(cache ? "transform-cache" : "transform-o3"),
                        Integer.toString(injections[0]));
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
            return writer.toByteArray();
        }
    }
}
