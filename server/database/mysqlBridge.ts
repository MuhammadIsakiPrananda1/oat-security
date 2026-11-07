import { Worker } from 'worker_threads';

/**
 * Synchronous MySQL bridge.
 *
 * The codebase was written against node:sqlite's synchronous API. Rewriting
 * every route to async would be a large, risky change, so the MySQL driver
 * runs in a worker thread and the main thread blocks on a SharedArrayBuffer
 * until the worker has answered. This keeps db.prepare().get()/all()/run()
 * semantics intact while the rows actually live in MySQL.
 *
 * Queries are serialized through one connection. That also makes BEGIN/COMMIT
 * blocks from the seed code work exactly as they did on SQLite.
 */

export interface MysqlBridgeConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
}

const CONTROL_BYTES = 16;
// Large enough for the biggest dashboard query; the worker returns an explicit
// error instead of truncating silently if a result ever exceeds this.
const DATA_BYTES = 64 * 1024 * 1024;
const QUERY_TIMEOUT_MS = 30_000;

const WORKER_SOURCE = String.raw`
const { parentPort, workerData } = require('worker_threads');
const mysql = require('mysql2/promise');

const ctrl = new Int32Array(workerData.control);
const data = new Uint8Array(workerData.data);
let connectionPromise = null;

function getConnection() {
  if (!connectionPromise) {
    connectionPromise = (async () => {
      try {
        const conn = await mysql.createConnection({
          host: workerData.db.host,
          port: workerData.db.port,
          user: workerData.db.user,
          password: workerData.db.password,
          database: workerData.db.database,
          charset: 'utf8mb4',
          multipleStatements: true,
          dateStrings: true,
          decimalNumbers: true,
          supportBigNumbers: true,
          bigNumberStrings: false,
          connectTimeout: 15000,
        });
        // SQLite was permissive about selecting non-aggregated columns. Keep that
        // behaviour (the dashboard's analytics queries rely on it) while leaving
        // the rest of MySQL's strict checks enabled.
        await conn.query(
          "SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'"
        );
        conn.on('error', (err) => {
          console.error('[MySQL Worker] Connection error:', err);
          connectionPromise = null;
        });
        return conn;
      } catch (err) {
        connectionPromise = null;
        throw err;
      }
    })();
  }
  return connectionPromise;
}

function respond(payload, isError) {
  const buf = Buffer.from(JSON.stringify(payload), 'utf8');
  if (buf.length > data.length) {
    const err = Buffer.from(JSON.stringify({ error: 'MySQL bridge response exceeds shared buffer' }), 'utf8');
    data.set(err, 0);
    ctrl[1] = err.length;
    ctrl[2] = 1;
  } else {
    data.set(buf, 0);
    ctrl[1] = buf.length;
    ctrl[2] = isError ? 1 : 0;
  }
  Atomics.store(ctrl, 0, 2);
  Atomics.notify(ctrl, 0);
}

parentPort.on('message', async (msg) => {
  try {
    const conn = await getConnection();

    if (msg.mode === 'exec') {
      // Raw query, no value formatting: schemas contain literal '%' in
      // DATE_FORMAT() defaults.
      await conn.query(msg.sql);
      respond({ ok: true });
      return;
    }

    const [rows] = await conn.query({ sql: msg.sql, values: msg.params || [] });

    if (msg.mode === 'get') {
      respond({ row: Array.isArray(rows) ? (rows[0] ?? null) : (rows ?? null) });
    } else if (msg.mode === 'all') {
      respond({ rows: Array.isArray(rows) ? rows : [] });
    } else {
      respond({
        affectedRows: rows && rows.affectedRows !== undefined ? rows.affectedRows : 0,
        insertId: rows && rows.insertId !== undefined ? rows.insertId : 0,
        changedRows: rows && rows.changedRows !== undefined ? rows.changedRows : 0,
      });
    }
  } catch (err) {
    respond(
      {
        error: err && err.message ? err.message : String(err),
        code: err && err.code,
        errno: err && err.errno,
        sqlState: err && err.sqlState,
      },
      true
    );
  }
});
`;

export class MysqlBridge {
  private worker: Worker;
  private control: Int32Array;
  private data: Uint8Array;

  constructor(config: MysqlBridgeConfig) {
    const controlBuffer = new SharedArrayBuffer(CONTROL_BYTES);
    const dataBuffer = new SharedArrayBuffer(DATA_BYTES);
    this.control = new Int32Array(controlBuffer);
    this.data = new Uint8Array(dataBuffer);

    this.worker = new Worker(WORKER_SOURCE, {
      eval: true,
      workerData: { control: controlBuffer, data: dataBuffer, db: config },
    });
    this.worker.unref();
    this.worker.on('error', (err) => {
      console.error('[MySQL Bridge] Worker error:', err);
    });
  }

  private call(payload: { mode: 'get' | 'all' | 'run' | 'exec'; sql: string; params?: unknown[] }): any {
    if (Atomics.load(this.control, 0) !== 0) {
      throw new Error('MySQL bridge is already executing a query');
    }

    this.worker.postMessage(payload);
    const result = Atomics.wait(this.control, 0, 0, QUERY_TIMEOUT_MS);
    if (result === 'timed-out') {
      throw new Error(`MySQL query timed out after ${QUERY_TIMEOUT_MS}ms`);
    }

    const length = Atomics.load(this.control, 1);
    const isError = Atomics.load(this.control, 2) === 1;
    const text = Buffer.from(this.data.subarray(0, length)).toString('utf8');
    Atomics.store(this.control, 0, 0);

    let parsed: any;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`Invalid response from MySQL worker: ${text.slice(0, 200)}`);
    }

    if (isError || parsed.error) {
      const err: any = new Error(parsed.error || 'MySQL query failed');
      err.code = parsed.code;
      err.errno = parsed.errno;
      err.sqlState = parsed.sqlState;
      err.sql = payload.sql;
      console.error(`[MySQL Bridge Error] SQL: ${payload.sql.slice(0, 150)} | Error:`, parsed.error);
      throw err;
    }
    return parsed;
  }

  query(mode: 'get' | 'all' | 'run', sql: string, params: unknown[] = []) {
    return this.call({ mode, sql, params });
  }

  exec(sql: string) {
    return this.call({ mode: 'exec', sql });
  }
}
