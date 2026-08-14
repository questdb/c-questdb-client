import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { connect } from "node:net";

import init, {
  QwpBrowserClient,
  QwpBrowserQuery,
} from "./web/pkg/questdb_qwp_browser.js";

const writeUrl = new URL(process.env.QWP_WS_URL ?? "ws://127.0.0.1:19000/api/v4/write");
const readUrl = new URL(process.env.QWP_READ_URL ?? "ws://127.0.0.1:19000/read/v1");
const origin = process.env.QWP_ORIGIN ?? "http://localhost:19000";

for (const endpoint of [writeUrl, readUrl]) {
  if (endpoint.protocol !== "ws:") {
    throw new Error(`smoke test only supports ws:// URLs, got ${endpoint.protocol}`);
  }
}

const wasm = await readFile(
  new URL("./web/pkg/questdb_qwp_browser_bg.wasm", import.meta.url),
);
await init({ module_or_path: wasm });

class RawWebSocket {
  constructor(socket, chunks, buffered) {
    this.socket = socket;
    this.chunks = chunks;
    this.buffered = buffered;
  }

  static async open(endpoint, requestOrigin) {
    const port = Number(endpoint.port || 80);
    const socket = connect({ host: endpoint.hostname, port });
    socket.setTimeout(10_000, () => socket.destroy(new Error("WebSocket smoke test timed out")));
    await new Promise((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });

    const chunks = socket[Symbol.asyncIterator]();
    let buffered = Buffer.alloc(0);
    const readMore = async () => {
      const { value, done } = await chunks.next();
      if (done) {
        throw new Error("QuestDB closed the WebSocket unexpectedly");
      }
      buffered = Buffer.concat([buffered, value]);
    };

    const key = randomBytes(16).toString("base64");
    socket.write([
      `GET ${endpoint.pathname}${endpoint.search} HTTP/1.1`,
      `Host: ${endpoint.host}`,
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${key}`,
      "Sec-WebSocket-Version: 13",
      `Origin: ${requestOrigin}`,
      "",
      "",
    ].join("\r\n"));

    let headerEnd = -1;
    while (headerEnd < 0) {
      await readMore();
      headerEnd = buffered.indexOf("\r\n\r\n");
    }
    const responseHeader = buffered.subarray(0, headerEnd + 4).toString("ascii");
    buffered = buffered.subarray(headerEnd + 4);
    if (!responseHeader.startsWith("HTTP/1.1 101 ")) {
      throw new Error(`WebSocket upgrade failed for ${endpoint.pathname}:\n${responseHeader}`);
    }

    const expectedAccept = createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    if (!responseHeader.toLowerCase().includes(`sec-websocket-accept: ${expectedAccept}`.toLowerCase())) {
      throw new Error("WebSocket upgrade returned an invalid Sec-WebSocket-Accept");
    }
    return new RawWebSocket(socket, chunks, buffered);
  }

  async readBytes(length) {
    while (this.buffered.length < length) {
      const { value, done } = await this.chunks.next();
      if (done) {
        throw new Error("QuestDB closed the WebSocket unexpectedly");
      }
      this.buffered = Buffer.concat([this.buffered, value]);
    }
    const result = this.buffered.subarray(0, length);
    this.buffered = this.buffered.subarray(length);
    return result;
  }

  sendFrame(opcode, payload) {
    const bytes = Buffer.from(payload);
    let extendedLength = 0;
    let lengthCode = bytes.length;
    if (bytes.length > 0xffff) {
      lengthCode = 127;
      extendedLength = 8;
    } else if (bytes.length > 125) {
      lengthCode = 126;
      extendedLength = 2;
    }
    const mask = randomBytes(4);
    const frame = Buffer.alloc(2 + extendedLength + mask.length + bytes.length);
    frame[0] = 0x80 | opcode;
    frame[1] = 0x80 | lengthCode;
    if (lengthCode === 126) {
      frame.writeUInt16BE(bytes.length, 2);
    } else if (lengthCode === 127) {
      frame.writeBigUInt64BE(BigInt(bytes.length), 2);
    }
    const maskOffset = 2 + extendedLength;
    mask.copy(frame, maskOffset);
    for (let i = 0; i < bytes.length; i += 1) {
      frame[maskOffset + 4 + i] = bytes[i] ^ mask[i & 3];
    }
    this.socket.write(frame);
  }

  sendBinary(payload) {
    this.sendFrame(0x02, payload);
  }

  async readBinary() {
    for (;;) {
      const header = await this.readBytes(2);
      const fin = (header[0] & 0x80) !== 0;
      const opcode = header[0] & 0x0f;
      if (!fin) {
        throw new Error("smoke test received a fragmented server WebSocket message");
      }
      if ((header[1] & 0x80) !== 0) {
        throw new Error("server WebSocket frames must not be masked");
      }
      let length = header[1] & 0x7f;
      if (length === 126) {
        length = (await this.readBytes(2)).readUInt16BE();
      } else if (length === 127) {
        length = Number((await this.readBytes(8)).readBigUInt64BE());
      }
      const payload = await this.readBytes(length);
      if (opcode === 0x09) {
        this.sendFrame(0x0a, payload);
        continue;
      }
      if (opcode === 0x08) {
        throw new Error(`server closed WebSocket: ${payload.toString("utf8")}`);
      }
      if (opcode !== 0x02) {
        throw new Error(`expected a binary response, got opcode 0x${opcode.toString(16)}`);
      }
      return payload;
    }
  }

  close() {
    this.socket.destroy();
  }
}

const ingressClient = new QwpBrowserClient();
const runQuantity = Date.now();
ingressClient.table("wasm_ticks");
ingressClient.symbol("symbol", "ETH-USD");
ingressClient.column_f64("price", 4242.5);
ingressClient.column_i64("quantity", BigInt(runQuantity));
ingressClient.column_bool("browser", true);
ingressClient.at_micros(BigInt(Date.now()) * 1000n);
const publishedFsn = ingressClient.publish();

// Drain once, then lose the connection before JavaScript hands the bytes to
// the socket. The shared Rust driver must retain and replay the same frame.
const failedSocket = await RawWebSocket.open(writeUrl, origin);
ingressClient.connection_opened();
const firstAttempt = ingressClient.next_payload();
failedSocket.close();
ingressClient.reset_connection();

const writeSocket = await RawWebSocket.open(writeUrl, origin);
ingressClient.connection_opened();
const writePayload = ingressClient.next_payload();
if (writePayload == null || Buffer.compare(Buffer.from(firstAttempt), Buffer.from(writePayload)) !== 0) {
  throw new Error("Rust replay driver did not reproduce the unresolved QWP frame after reconnect");
}
writeSocket.sendBinary(writePayload);
const ackPayload = await writeSocket.readBinary();
ingressClient.handle_response(ackPayload);
const ack = ingressClient.describe_response(ackPayload);
if (ingressClient.acked_fsn() !== publishedFsn) {
  throw new Error(`ACK watermark did not reach published fsn ${publishedFsn}`);
}
writeSocket.close();

const queryClient = new QwpBrowserQuery();
const readSocket = await RawWebSocket.open(readUrl, origin);
const serverInfo = JSON.parse(queryClient.decode_frame(await readSocket.readBinary()));
if (serverInfo.kind !== "server_info") {
  throw new Error(`expected SERVER_INFO, got ${JSON.stringify(serverInfo)}`);
}

let insertedRow;
let queryEvents;
for (let attempt = 0; attempt < 50 && !insertedRow; attempt += 1) {
  const sql = `select symbol, price, quantity, browser from wasm_ticks where quantity = ${runQuantity}`;
  readSocket.sendBinary(queryClient.encode_query(sql));
  queryEvents = [];
  for (;;) {
    const event = JSON.parse(queryClient.decode_frame(await readSocket.readBinary()));
    queryEvents.push(event);
    if (event.kind === "batch") {
      insertedRow = event.rows.find(
        (row) => row[0] === "ETH-USD" && row[1] === "4242.5" && row[2] === String(runQuantity) && row[3] === "true",
      );
    }
    if (event.kind === "error") {
      throw new Error(`QWP query failed: ${event.message}`);
    }
    if (event.kind === "end" || event.kind === "exec_done") {
      break;
    }
  }
  if (!insertedRow) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}
readSocket.close();

if (!insertedRow) {
  throw new Error(`inserted row was not returned over QWP egress: ${JSON.stringify(queryEvents)}`);
}

console.log(`upgrade accepted Origin ${origin} for QWP ingress and egress`);
console.log(`replayed and ACKed fsn ${publishedFsn}; sent ${writePayload.byteLength} WASM-generated QWP bytes; ${ack}`);
console.log(`QWP egress ${serverInfo.role} node=${serverInfo.node_id}; queried row ${JSON.stringify(insertedRow)}`);
