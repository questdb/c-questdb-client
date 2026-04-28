import io.questdb.client.cutlass.qwp.client.GlobalSymbolDictionary;
import io.questdb.client.cutlass.qwp.client.QwpBufferWriter;
import io.questdb.client.cutlass.qwp.client.QwpWebSocketEncoder;
import io.questdb.client.cutlass.qwp.protocol.QwpConstants;
import io.questdb.client.cutlass.qwp.protocol.QwpTableBuffer;
import io.questdb.client.std.Unsafe;

public final class QwpGoldenGenerator {
    private static final int SYMBOL_COUNT = 10;
    private static final long BASE_TS_NANOS = 1_700_000_000_000_000_000L;

    public static void main(String[] args) {
        GlobalSymbolDictionary globalDict = new GlobalSymbolDictionary();
        try (QwpWebSocketEncoder encoder = new QwpWebSocketEncoder()) {
            byte[] first = encodeFirst(encoder, globalDict);
            byte[] second = encodeSecond(encoder, globalDict);
            print("first", first);
            print("second", second);
        }
    }

    private static byte[] encodeFirst(QwpWebSocketEncoder encoder, GlobalSymbolDictionary globalDict) {
        try (QwpTableBuffer table = new QwpTableBuffer("trades")) {
            for (int idx = 0; idx < SYMBOL_COUNT; idx++) {
                String sym = String.format("SYM_%03d", idx);
                int globalId = globalDict.getOrAddSymbol(sym);
                table.getOrCreateColumn("sym", QwpConstants.TYPE_SYMBOL, false)
                        .addSymbolWithGlobalId(sym, globalId);
                table.getOrCreateColumn("qty", QwpConstants.TYPE_LONG, false)
                        .addLong(idx);
                table.getOrCreateColumn("px", QwpConstants.TYPE_DOUBLE, false)
                        .addDouble(100.0 + idx);
                table.getOrCreateDesignatedTimestampColumn(QwpConstants.TYPE_TIMESTAMP_NANOS)
                        .addLong(BASE_TS_NANOS + idx);
                table.nextRow();
            }
            return encodeReplay(encoder, table, globalDict, SYMBOL_COUNT - 1);
        }
    }

    private static byte[] encodeSecond(QwpWebSocketEncoder encoder, GlobalSymbolDictionary globalDict) {
        try (QwpTableBuffer table = new QwpTableBuffer("trades")) {
            String sym = "SYM_009";
            int globalId = globalDict.getOrAddSymbol(sym);
            table.getOrCreateColumn("sym", QwpConstants.TYPE_SYMBOL, false)
                    .addSymbolWithGlobalId(sym, globalId);
            table.getOrCreateColumn("qty", QwpConstants.TYPE_LONG, false)
                    .addLong(99);
            table.getOrCreateColumn("px", QwpConstants.TYPE_DOUBLE, false)
                    .addDouble(999.5);
            table.getOrCreateDesignatedTimestampColumn(QwpConstants.TYPE_TIMESTAMP_NANOS)
                    .addLong(BASE_TS_NANOS + 1_000);
            table.nextRow();
            return encodeReplay(encoder, table, globalDict, SYMBOL_COUNT - 1);
        }
    }

    private static byte[] encodeReplay(
            QwpWebSocketEncoder encoder,
            QwpTableBuffer table,
            GlobalSymbolDictionary globalDict,
            int batchMaxId
    ) {
        encoder.beginMessage(1, globalDict, -1, batchMaxId);
        encoder.addTable(table, false);
        int len = encoder.finishMessage();
        return copy(encoder.getBuffer(), len);
    }

    private static byte[] copy(QwpBufferWriter buffer, int len) {
        byte[] out = new byte[len];
        long ptr = buffer.getBufferPtr();
        for (int i = 0; i < len; i++) {
            out[i] = Unsafe.getUnsafe().getByte(ptr + i);
        }
        return out;
    }

    private static void print(String name, byte[] bytes) {
        System.out.printf("%s_len=%d%n", name, bytes.length);
        System.out.printf("%s_hex=%s%n", name, hex(bytes));
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >>> 4) & 0xF, 16));
            out.append(Character.forDigit(b & 0xF, 16));
        }
        return out.toString();
    }
}
