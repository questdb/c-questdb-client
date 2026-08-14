import init, { QwpBrowserClient, QwpBrowserQuery } from "./pkg/questdb_qwp_browser.js";

await init();

const client = new QwpBrowserClient();
const queryClient = new QwpBrowserQuery();
const url = document.querySelector("#url");
const queryUrl = document.querySelector("#query-url");
const connect = document.querySelector("#connect");
const send = document.querySelector("#send");
const close = document.querySelector("#close");
const logOutput = document.querySelector("#log");
const sql = document.querySelector("#sql");
const executeSql = document.querySelector("#execute-sql");
const queryStatus = document.querySelector("#query-status");
const queryResult = document.querySelector("#query-result");
let socket = null;
let ingressEndpoints = [];
let ingressEndpointIndex = 0;
let ingressReconnectTimer = null;
let ingressManualClose = false;
let querySocket = null;
let querySocketPromise = null;
let queryColumns = [];
let queryRows = [];

if (window.location.port !== "5173") {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  url.value = `${protocol}//${window.location.host}/api/v4/write`;
  queryUrl.value = `${protocol}//${window.location.host}/read/v1`;
}

function log(message) {
  const timestamp = new Date().toISOString();
  logOutput.textContent += `${timestamp} ${message}\n`;
  logOutput.scrollTop = logOutput.scrollHeight;
}

function configuredIngressEndpoints() {
  return url.value.split(",").map((value) => value.trim()).filter(Boolean);
}

function drainIngress() {
  if (socket?.readyState !== WebSocket.OPEN) return;
  for (;;) {
    const payload = client.next_payload();
    if (payload == null) break;
    try {
      socket.send(payload);
      log(`sent ${payload.byteLength} retained QWP payload bytes`);
    } catch (error) {
      log(`WebSocket.send failed; unresolved frame stays queued: ${error}`);
      socket.close(1011, "send failure");
      break;
    }
  }
}

function disconnected() {
  send.disabled = true;
  socket = null;
  client.reset_connection();
  if (ingressManualClose || ingressEndpoints.length === 0) {
    connect.disabled = false;
    close.disabled = true;
    return;
  }
  ingressEndpointIndex = (ingressEndpointIndex + 1) % ingressEndpoints.length;
  const delay = ingressEndpoints.length > 1 ? 50 : 500;
  log(`failing over to ${ingressEndpoints[ingressEndpointIndex]} in ${delay} ms`);
  clearTimeout(ingressReconnectTimer);
  ingressReconnectTimer = setTimeout(connectIngress, delay);
}

function connectIngress() {
  const endpoint = ingressEndpoints[ingressEndpointIndex];
  log(`connecting to ${endpoint}`);
  const ws = new WebSocket(endpoint);
  socket = ws;
  ws.binaryType = "arraybuffer";

  ws.addEventListener("open", () => {
    if (socket !== ws) return;
    client.connection_opened();
    log(`connected to ${endpoint}`);
    send.disabled = false;
    close.disabled = false;
    drainIngress();
  });
  ws.addEventListener("message", (event) => {
    try {
      const payload = new Uint8Array(event.data);
      client.handle_response(payload);
      log(`${client.describe_response(payload)}; acked_fsn=${client.acked_fsn() ?? "none"}`);
      if (client.reconnect_requested()) {
        log("Rust QWP driver requested endpoint failover");
        ws.close(1000, "QWP failover");
      } else {
        drainIngress();
      }
    } catch (error) {
      log(`could not apply QWP response: ${error}`);
      ws.close(1002, "QWP response failure");
    }
  });
  ws.addEventListener("error", () => log(`WebSocket error from ${endpoint}`));
  ws.addEventListener("close", (event) => {
    if (socket !== ws) return;
    log(`closed ${endpoint} code=${event.code} reason=${event.reason || "<none>"}`);
    disconnected();
  });
}

connect.addEventListener("click", () => {
  ingressEndpoints = configuredIngressEndpoints();
  if (ingressEndpoints.length === 0) {
    log("configure at least one QWP ingestion WebSocket URL");
    return;
  }
  ingressEndpointIndex = 0;
  ingressManualClose = false;
  connect.disabled = true;
  connectIngress();
});

send.addEventListener("click", () => {
  try {
    client.clear();
    client.table("wasm_ticks");
    client.symbol("symbol", "ETH-USD");
    client.column_f64("price", 4242.5);
    client.column_i64("quantity", 7n);
    client.column_bool("browser", true);
    client.at_micros(BigInt(Date.now()) * 1000n);

    const fsn = client.publish();
    log(`published fsn=${fsn} into Rust replay queue`);
    drainIngress();
  } catch (error) {
    log(`send failed: ${error}`);
  }
});

close.addEventListener("click", () => {
  ingressManualClose = true;
  clearTimeout(ingressReconnectTimer);
  socket?.close(1000, "prototype complete");
});

function appendCell(row, tag, value) {
  const cell = document.createElement(tag);
  cell.textContent = value == null
    ? "NULL"
    : typeof value === "object"
      ? JSON.stringify(value)
      : String(value);
  row.append(cell);
}

function renderQueryResult(columns, rows) {
  queryResult.replaceChildren();
  const table = document.createElement("table");
  const head = document.createElement("thead");
  const headerRow = document.createElement("tr");
  for (const column of columns) {
    appendCell(headerRow, "th", `${column.name} (${column.type})`);
  }
  head.append(headerRow);
  table.append(head);

  const body = document.createElement("tbody");
  for (const values of rows) {
    const row = document.createElement("tr");
    for (const value of values) {
      appendCell(row, "td", value);
    }
    body.append(row);
  }
  table.append(body);
  queryResult.append(table);
}

function handleQueryEvent(event) {
  switch (event.kind) {
    case "server_info":
      queryStatus.textContent = `Connected to ${event.node_id || event.role} (${event.role}).`;
      break;
    case "cache_reset":
      break;
    case "batch":
      if (event.batch_seq === 0) {
        queryColumns = event.columns;
        queryRows = [];
      }
      queryRows.push(...event.rows);
      renderQueryResult(queryColumns, queryRows);
      queryStatus.textContent = `Streaming: ${queryRows.length} row${queryRows.length === 1 ? "" : "s"}…`;
      break;
    case "end":
      queryStatus.textContent = `Completed over QWP: ${event.total_rows} row${event.total_rows === 1 ? "" : "s"}.`;
      executeSql.disabled = false;
      break;
    case "exec_done":
      queryStatus.textContent = `Completed over QWP: ${event.rows_affected} row${event.rows_affected === 1 ? "" : "s"} affected.`;
      executeSql.disabled = false;
      break;
    case "error":
      queryStatus.textContent = `QWP query failed (status 0x${event.status.toString(16).padStart(2, "0")}): ${event.message}`;
      executeSql.disabled = false;
      break;
    default:
      throw new Error(`unknown QWP query event: ${event.kind}`);
  }
}

function ensureQuerySocket() {
  if (querySocket?.readyState === WebSocket.OPEN) {
    return Promise.resolve(querySocket);
  }
  if (querySocketPromise) {
    return querySocketPromise;
  }

  queryStatus.textContent = `Connecting to ${queryUrl.value}…`;
  querySocketPromise = new Promise((resolve, reject) => {
    const ws = new WebSocket(queryUrl.value);
    querySocket = ws;
    ws.binaryType = "arraybuffer";
    ws.addEventListener("open", () => resolve(ws), { once: true });
    ws.addEventListener("message", (message) => {
      try {
        handleQueryEvent(JSON.parse(queryClient.decode_frame(new Uint8Array(message.data))));
      } catch (error) {
        queryStatus.textContent = `Could not decode QWP query response: ${error.message ?? error}`;
        executeSql.disabled = false;
        ws.close(1002, "QWP decode failure");
      }
    });
    ws.addEventListener("error", () => reject(new Error("QWP query WebSocket error")), { once: true });
    ws.addEventListener("close", (event) => {
      if (querySocket === ws) {
        querySocket = null;
        querySocketPromise = null;
        queryClient.reset_connection();
      }
      if (executeSql.disabled) {
        queryStatus.textContent = `QWP query connection closed (code ${event.code}).`;
        executeSql.disabled = false;
      }
    });
  });
  return querySocketPromise;
}

executeSql.addEventListener("click", async () => {
  const statement = sql.value.trim();
  if (!statement) {
    queryStatus.textContent = "Enter a SQL statement.";
    return;
  }

  executeSql.disabled = true;
  queryStatus.textContent = "Executing over QWP…";
  queryResult.replaceChildren();
  queryColumns = [];
  queryRows = [];
  try {
    const ws = await ensureQuerySocket();
    const payload = queryClient.encode_query(statement);
    ws.send(payload);
  } catch (error) {
    queryStatus.textContent = `Query failed: ${error.message ?? error}`;
    executeSql.disabled = false;
  }
});
