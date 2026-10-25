'use strict';
// SPDX-License-Identifier: CC0-1.0
// =============================================================================
// brotli-guard - in-process stopgap for CVE-2026-111497 (Node.js Brotli
// decoder out-of-bounds write, fixed in 22.23.4 / 24.22.1 / 26.12.1)
//
// If this software is helpful, consider a donation to our 501c3 nonprofit:
// https://privacysafe.foundation
//
// Load it before any application code:
//
//   node --require /usr/local/lib/privacysafe/brotli-guard.cjs app.js
//   NODE_OPTIONS="--require=/usr/local/lib/privacysafe/brotli-guard.cjs" ...
//
// node-oct2026-mitigate.sh `guard --unit <name>` does this for a systemd unit.
//
// What it does: every way JavaScript reaches Node's Brotli decoder goes through
// node:zlib (brotliDecompress, brotliDecompressSync, createBrotliDecompress,
// new BrotliDecompress). This replaces those four entry points, for CommonJS
// and ES modules, with versions that refuse to decode. Brotli *compression* is
// untouched; only the decoder has the bug. Built-in fetch() is also told to
// stop advertising "br" in Accept-Encoding, so well-behaved servers send gzip
// instead. A server that sends Brotli anyway gets a decode error, not a decode.
//
// The refusal looks like corrupt input: callbacks get an error, sync calls
// throw, streams emit 'error' on the first chunk. Code that already copes with
// a bad compressed body copes with this too.
//
// Environment:
//   BROTLI_GUARD=block   refuse to decode (default)
//   BROTLI_GUARD=log     decode normally but report each caller, so you can
//                        see what in your app (or its dependencies) uses Brotli
//   BROTLI_GUARD=off     do nothing
//   BROTLI_GUARD_FORCE=1 stay active on a runtime that already has the fix
//   BROTLI_GUARD_QUIET=1 don't print the one-line "active" notice at startup
//
// Run it directly to test it on this runtime:
//   node brotli-guard.cjs --self-test
//
// Limits: it covers Node's decoder as reached from JavaScript. A native addon
// that calls the bundled Brotli library directly, or code that saved a
// reference to the zlib functions before this file loaded, is not covered.
// That's why it has to be the first thing loaded. Upgrade Node; then drop this.
// =============================================================================

const GUARD_VERSION = '1.0.0';
const FIXED = { 22: '22.23.4', 24: '24.22.1', 26: '26.12.1' };
const MARK = Symbol.for('privacysafe.brotliGuard');
const TAG = '[brotli-guard]';

function verCmp(a, b) {
    const x = a.split('.').map(Number), y = b.split('.').map(Number);
    for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); }
    return 0;
}

function runtimeFixed(v = process.versions.node) {
    const f = FIXED[Number(v.split('.')[0])];
    return Boolean(f && verCmp(v, f) >= 0);
}

function install(opts = {}) {
    const mode = String(opts.mode || process.env.BROTLI_GUARD || 'block').toLowerCase();
    const force = opts.force ?? process.env.BROTLI_GUARD_FORCE === '1';
    const quiet = opts.quiet ?? process.env.BROTLI_GUARD_QUIET === '1';
    const say = (msg) => { try { process.stderr.write(`${TAG} ${msg}\n`); } catch { /* no stderr */ } };

    if (globalThis[MARK]) return globalThis[MARK];
    if (mode === 'off') return (globalThis[MARK] = { active: false, reason: 'BROTLI_GUARD=off' });
    if (mode !== 'block' && mode !== 'log') {
        say(`unknown BROTLI_GUARD=${mode}; using block`);
    }
    const blocking = mode !== 'log';
    if (runtimeFixed() && !force) {
        if (!quiet) say(`Node ${process.version} has the CVE-2026-111497 fix; guard idle. Remove it from NODE_OPTIONS when convenient.`);
        return (globalThis[MARK] = { active: false, reason: 'runtime fixed' });
    }

    const zlib = require('node:zlib');
    const { Transform } = require('node:stream');
    const seen = new Set();

    // One report per API and call site: enough to find the dependency
    // responsible without flooding logs on a busy server.
    function report(api) {
        const stack = String(new Error().stack);
        const frames = stack.split('\n').slice(1).map((s) => s.trim())
            .filter((s) => !s.includes(__filename) && !s.includes('node:internal') && !s.includes('wasm://'));
        // Built-in fetch() decodes from inside undici's parser, where the
        // caller's frames are already gone
        const site = frames[0] || (stack.includes('deps/undici') ? '(built-in fetch)' : 'unknown caller');
        const key = `${api}|${site}`;
        if (seen.has(key)) return;
        if (seen.size < 500) seen.add(key);
        say(`${blocking ? 'blocked' : 'saw'} ${api} pid=${process.pid} ${site}`);
    }

    function refusal(api) {
        const err = new Error(`${api}: Brotli decoding is disabled by brotli-guard ` +
            `(CVE-2026-111497) until Node is upgraded to ${Object.values(FIXED).join(' / ')}`);
        err.code = 'ERR_BROTLI_GUARD_BLOCKED';
        return err;
    }

    // A stream that fails on the first chunk (or at end, for an empty body).
    // Failing on data rather than at creation means pipe()/pipeline() have
    // already attached their error handlers, so the error is handled the same
    // way a corrupt body would be. The error is raised on the next turn of the
    // event loop: undici writes response bytes from inside its HTTP parser, and
    // an error raised synchronously there leaves fetch() hanging instead of
    // rejecting.
    function refusingStream(api) {
        return new Transform({
            transform(_chunk, _enc, cb) { setImmediate(cb, refusal(api)); },
            flush(cb) { setImmediate(cb, refusal(api)); },
        });
    }

    const orig = {
        brotliDecompress: zlib.brotliDecompress,
        brotliDecompressSync: zlib.brotliDecompressSync,
        createBrotliDecompress: zlib.createBrotliDecompress,
        BrotliDecompress: zlib.BrotliDecompress,
    };

    const patched = {
        brotliDecompress: function brotliDecompress(buf, options, callback) {
            report('zlib.brotliDecompress');
            if (!blocking) return orig.brotliDecompress.apply(this, arguments);
            const cb = typeof options === 'function' ? options : callback;
            if (typeof cb !== 'function') return orig.brotliDecompress.apply(this, arguments); // let Node raise its own TypeError
            process.nextTick(cb, refusal('zlib.brotliDecompress'));
        },
        brotliDecompressSync: function brotliDecompressSync() {
            report('zlib.brotliDecompressSync');
            if (!blocking) return orig.brotliDecompressSync.apply(this, arguments);
            throw refusal('zlib.brotliDecompressSync');
        },
        createBrotliDecompress: function createBrotliDecompress() {
            report('zlib.createBrotliDecompress');
            if (!blocking) return orig.createBrotliDecompress.apply(this, arguments);
            return refusingStream('zlib.createBrotliDecompress');
        },
        // Callable with or without `new`, like the original. `instanceof
        // zlib.BrotliDecompress` stops matching; nothing we know of relies on it.
        BrotliDecompress: function BrotliDecompress(...args) {
            report('zlib.BrotliDecompress');
            if (!blocking) return Reflect.construct(orig.BrotliDecompress, args);
            return refusingStream('new zlib.BrotliDecompress');
        },
    };

    for (const [name, fn] of Object.entries(patched)) {
        Object.defineProperty(zlib, name, { value: fn, writable: true, configurable: true, enumerable: true });
    }
    // Keep util.promisify(zlib.brotliDecompress) working: no custom symbol on
    // the replacement, so promisify wraps the callback form above.
    // Push the new bindings into `import { ... } from 'node:zlib'` as well.
    try { require('node:module').syncBuiltinESMExports(); } catch { /* very old runtime */ }

    // fetch(): if the caller didn't choose an Accept-Encoding, choose one
    // without "br". undici decodes through zlib.createBrotliDecompress, so a
    // server that ignores this still only reaches the refusal above.
    if (typeof globalThis.fetch === 'function' && typeof globalThis.Headers === 'function') {
        const origFetch = globalThis.fetch;
        const guardedFetch = function fetch(input, init) {
            try {
                const fromReq = typeof Request === 'function' && input instanceof Request;
                const src = init && init.headers !== undefined ? init.headers : (fromReq ? input.headers : undefined);
                const h = new Headers(src);
                if (!h.has('accept-encoding')) {
                    h.set('accept-encoding', 'gzip, deflate');
                    init = Object.assign({}, init, { headers: h });
                }
            } catch { /* leave the request exactly as the caller built it */ }
            return origFetch.call(this, input, init);
        };
        Object.defineProperty(globalThis, 'fetch', { value: guardedFetch, writable: true, configurable: true, enumerable: false });
    }

    const state = { active: true, mode: blocking ? 'block' : 'log', version: GUARD_VERSION, restore() {
        for (const [name, fn] of Object.entries(orig)) {
            Object.defineProperty(zlib, name, { value: fn, writable: true, configurable: true, enumerable: true });
        }
        try { require('node:module').syncBuiltinESMExports(); } catch { /* ignore */ }
    } };
    globalThis[MARK] = state;
    if (!quiet) say(`active v${GUARD_VERSION} mode=${state.mode} node=${process.version} pid=${process.pid}`);
    return state;
}

// ---------- self-test --------------------------------------------------------
async function selfTest() {
    const results = [];
    const check = async (name, fn) => {
        try { await fn(); results.push([true, name]); } catch (e) { results.push([false, `${name}: ${e.message}`]); }
    };
    const expectBlocked = (e) => {
        if (!e || e.code !== 'ERR_BROTLI_GUARD_BLOCKED') throw new Error(`expected ERR_BROTLI_GUARD_BLOCKED, got ${e ? (e.code || e.message) : 'success'}`);
    };

    console.log(`brotli-guard ${GUARD_VERSION} self-test on Node ${process.version} ` +
        `(${runtimeFixed() ? 'runtime has the fix' : 'runtime NOT fixed'})`);
    const st = install({ mode: 'block', force: true, quiet: true });
    if (!st.active) { console.log(`not active: ${st.reason}`); process.exit(1); }

    const zlib = require('node:zlib');
    const sample = zlib.brotliCompressSync(Buffer.from('privacysafe '.repeat(200)));

    await check('compression still works', () => {
        if (!Buffer.isBuffer(sample) || sample.length === 0) throw new Error('brotliCompressSync failed');
    });
    await check('brotliDecompressSync refuses', () => {
        try { zlib.brotliDecompressSync(sample); } catch (e) { return expectBlocked(e); }
        expectBlocked(null);
    });
    await check('brotliDecompress refuses (callback)', () => new Promise((res, rej) => {
        zlib.brotliDecompress(sample, (e) => { try { expectBlocked(e); res(); } catch (x) { rej(x); } });
    }));
    await check('brotliDecompress refuses (promisified)', async () => {
        const p = require('node:util').promisify(zlib.brotliDecompress);
        try { await p(sample); } catch (e) { return expectBlocked(e); }
        expectBlocked(null);
    });
    await check('createBrotliDecompress stream refuses', async () => {
        const { pipeline } = require('node:stream/promises');
        const { Readable, Writable } = require('node:stream');
        try {
            await pipeline(Readable.from([sample]), zlib.createBrotliDecompress(), new Writable({ write(_c, _e, cb) { cb(); } }));
        } catch (e) { return expectBlocked(e); }
        expectBlocked(null);
    });
    await check('new BrotliDecompress refuses', () => new Promise((res, rej) => {
        const s = new zlib.BrotliDecompress();
        s.on('error', (e) => { try { expectBlocked(e); res(); } catch (x) { rej(x); } });
        s.on('data', () => rej(new Error('decoded data')));
        s.end(sample);
    }));
    await check('ES module import sees the guard', async () => {
        const m = await import('node:zlib');
        try { m.brotliDecompressSync(sample); } catch (e) { return expectBlocked(e); }
        expectBlocked(null);
    });
    await check('gzip still decodes', () => {
        const out = zlib.gunzipSync(zlib.gzipSync(Buffer.from('ok'))).toString();
        if (out !== 'ok') throw new Error('gzip round trip failed');
    });

    if (typeof fetch === 'function') {
        const http = require('node:http');
        let seenAE = null;
        const srv = http.createServer((req, res) => {
            seenAE = req.headers['accept-encoding'];
            // Send Brotli whatever the client asked for: the case a hostile server creates
            res.writeHead(200, { 'content-encoding': 'br', 'content-type': 'text/plain' });
            res.end(sample);
        });
        await new Promise((r) => srv.listen(0, '127.0.0.1', r));
        const url = `http://127.0.0.1:${srv.address().port}/`;
        await check('fetch() drops "br" from Accept-Encoding', async () => {
            const r = await fetch(url); await r.arrayBuffer().catch(() => {});
            if (/\bbr\b/i.test(seenAE || '')) throw new Error(`sent accept-encoding: ${seenAE}`);
        });
        await check('fetch() refuses a Brotli body it did not ask for', async () => {
            let body;
            try { const r = await fetch(url); body = await r.text(); } catch (e) {
                const c = e && (e.cause || e);
                if (c && c.code === 'ERR_BROTLI_GUARD_BLOCKED') return;
                if (/brotli-guard/.test(String(e && e.message) + String(c && c.message))) return;
                throw new Error(`failed, but not by the guard: ${e.message}`);
            }
            if (body && body.includes('privacysafe')) throw new Error('fetch decoded the Brotli body');
        });
        srv.close();
    } else {
        results.push([true, 'fetch() not present on this runtime (skipped)']);
    }

    let bad = 0;
    for (const [ok, msg] of results) { console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${msg}`); if (!ok) bad++; }
    console.log(bad ? `${bad} check(s) failed - do not rely on the guard on this runtime` : 'all checks passed');
    process.exit(bad ? 1 : 0);
}

if (require.main === module) {
    if (process.argv.includes('--self-test')) selfTest();
    else if (process.argv.includes('--version')) console.log(GUARD_VERSION);
    else { console.log('Load with --require, or run with --self-test. See the header of this file.'); }
} else {
    install();
}

module.exports = { install, runtimeFixed, GUARD_VERSION, FIXED };

// Assisted-by: Claude Opus 5.5
