'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const runtime = require('../runtime/node/shellguard.js');

const ROOT = path.resolve(__dirname, '..');
const RULES = path.join(ROOT, 'runtime', 'rules.json');

function tempLog() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'shellguard-node-test-'));
  return {
    directory,
    logPath: path.join(directory, 'runtime.jsonl'),
  };
}

function fakeRequest(urlValue, ip = '127.0.0.1') {
  return {
    url: urlValue,
    headers: {},
    socket: { remoteAddress: ip },
  };
}

function fakeResponse() {
  return {
    statusCode: 200,
    headers: {},
    body: '',
    setHeader(name, value) {
      this.headers[name] = value;
    },
    end(value) {
      this.body += value || '';
    },
  };
}

function readLog(logPath) {
  return fs.readFileSync(logPath, 'utf8')
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

test('monitor middleware logs a harmless marker and calls next', () => {
  const { directory, logPath } = tempLog();
  try {
    const middleware = runtime.createMiddleware({ mode: 'monitor', logPath, rulesPath: RULES });
    const response = fakeResponse();
    let nextCalled = false;
    middleware(
      fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'),
      response,
      () => { nextCalled = true; },
    );
    assert.equal(nextCalled, true);
    assert.equal(response.statusCode, 200);
    assert.equal(readLog(logPath)[0].rule_id, 'REQUEST-COMMAND-PARAMETER');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('request values are decoded twice and expanded command names are inspected', () => {
  const { directory, logPath } = tempLog();
  try {
    const middleware = runtime.createMiddleware({ mode: 'monitor', logPath, rulesPath: RULES });
    middleware(fakeRequest('/echo?action=eval%2528x%2529'), fakeResponse(), () => {});
    middleware(fakeRequest('/echo?action=echo%20SHELLGUARD_TEST_MARKER'), fakeResponse(), () => {});
    const ids = new Set(readLog(logPath).map((event) => event.rule_id));
    assert.equal(ids.has('REQUEST-EXECUTION-PATTERN'), true);
    assert.equal(ids.has('REQUEST-COMMAND-PARAMETER'), true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('block middleware returns 403 without running the endpoint', () => {
  const { directory, logPath } = tempLog();
  try {
    const middleware = runtime.createMiddleware({ mode: 'block', logPath, rulesPath: RULES });
    const response = fakeResponse();
    let nextCalled = false;
    middleware(
      fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'),
      response,
      () => { nextCalled = true; },
    );
    assert.equal(nextCalled, false);
    assert.equal(response.statusCode, 403);
    assert.match(response.body, /blocked/i);
    assert.equal(readLog(logPath)[0].mode, 'block');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('IP and path allowlists bypass request protection', () => {
  const { directory, logPath } = tempLog();
  try {
    const middleware = runtime.createMiddleware({
      mode: 'block',
      logPath,
      rulesPath: RULES,
      ipAllowlist: ['127.0.0.1'],
    });
    const response = fakeResponse();
    let nextCalled = false;
    middleware(fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'), response, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.equal(fs.existsSync(logPath), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('IP CIDR allowlists match IPv4 and IPv6 clients', () => {
  const { directory, logPath } = tempLog();
  try {
    const ipv4Middleware = runtime.createMiddleware({
      mode: 'block',
      logPath,
      rulesPath: RULES,
      ipAllowlist: ['192.0.2.0/24'],
    });
    const ipv4Response = fakeResponse();
    let ipv4NextCalled = false;
    ipv4Middleware(
      fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER', '192.0.2.44'),
      ipv4Response,
      () => { ipv4NextCalled = true; },
    );
    assert.equal(ipv4NextCalled, true);
    assert.equal(ipv4Response.statusCode, 200);

    const ipv6Middleware = runtime.createMiddleware({
      mode: 'block',
      logPath,
      rulesPath: RULES,
      ipAllowlist: ['2001:db8::/32'],
    });
    const ipv6Response = fakeResponse();
    let ipv6NextCalled = false;
    ipv6Middleware(
      fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER', '2001:db8::44'),
      ipv6Response,
      () => { ipv6NextCalled = true; },
    );
    assert.equal(ipv6NextCalled, true);
    assert.equal(ipv6Response.statusCode, 200);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('wildcard allowlists emit clear warnings', () => {
  const { directory } = tempLog();
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (message) => warnings.push(String(message));
  try {
    runtime.loadConfig({
      configPath: path.join(directory, 'config.json'),
      ipAllowlist: ['*'],
      pathAllowlist: ['/*'],
    });
    assert.ok(warnings.some((message) => message.includes('ip_allowlist contains "*"')));
    assert.ok(warnings.some((message) => message.includes('path_allowlist contains "/*"')));
  } finally {
    console.warn = originalWarn;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('default log path is private and log files are restrictive on POSIX', () => {
  const { directory } = tempLog();
  try {
    const config = runtime.loadConfig({
      configPath: path.join(directory, 'config.json'),
      rulesPath: RULES,
    });
    assert.notEqual(path.dirname(config.logPath), os.tmpdir());
    const middleware = runtime.createMiddleware({
      configPath: path.join(directory, 'config.json'),
      rulesPath: RULES,
    });
    middleware(fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'), fakeResponse(), () => {});
    assert.equal(fs.existsSync(config.logPath), true);
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(config.logPath).mode & 0o777, 0o600);
    }
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('runtime request regexes are compiled once per middleware', () => {
  const { directory, logPath } = tempLog();
  const originalRegExp = global.RegExp;
  let constructions = 0;
  global.RegExp = function countedRegExp(...args) {
    constructions += 1;
    return new originalRegExp(...args);
  };
  try {
    const middleware = runtime.createMiddleware({ mode: 'monitor', logPath, rulesPath: RULES });
    const afterCreate = constructions;
    middleware(fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'), fakeResponse(), () => {});
    middleware(fakeRequest('/echo?cmd=echo%20SHELLGUARD_TEST_MARKER'), fakeResponse(), () => {});
    assert.equal(constructions, afterCreate);
  } finally {
    global.RegExp = originalRegExp;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('child process guard covers execFile, execFileSync, and fork', () => {
  const { directory, logPath } = tempLog();
  const calls = [];
  const fakeChildProcess = {
    exec(command, callback) {
      calls.push(command);
      if (callback) callback(null, 'harmless fake output');
    },
    execSync(command) {
      calls.push(command);
      return Buffer.from('harmless fake output');
    },
    execFile(command, _args, callback) {
      calls.push(command);
      if (callback) callback(null, 'harmless fake output');
    },
    execFileSync(command) {
      calls.push(command);
      return Buffer.from('harmless fake output');
    },
    spawn(command) {
      calls.push(command);
      return { command };
    },
    spawnSync(command) {
      calls.push(command);
      return { command };
    },
    fork(command) {
      calls.push(command);
      return { command };
    },
  };
  try {
    const restoreMonitor = runtime.installChildProcessGuard({
      childProcess: fakeChildProcess,
      mode: 'monitor',
      logPath,
      allowlist: ['safe-tool'],
    });
    fakeChildProcess.exec('SHELLGUARD_TEST_MARKER', () => {});
    fakeChildProcess.execFile('SHELLGUARD_TEST_MARKER', [], () => {});
    fakeChildProcess.execFileSync('SHELLGUARD_TEST_MARKER');
    fakeChildProcess.fork('SHELLGUARD_TEST_MARKER');
    restoreMonitor();
    assert.deepEqual(calls, [
      'SHELLGUARD_TEST_MARKER',
      'SHELLGUARD_TEST_MARKER',
      'SHELLGUARD_TEST_MARKER',
      'SHELLGUARD_TEST_MARKER',
    ]);
    assert.equal(readLog(logPath)[0].type, 'child_process_call');

    const restoreBlock = runtime.installChildProcessGuard({
      childProcess: fakeChildProcess,
      mode: 'block',
      logPath,
      allowlist: [],
    });
    assert.throws(() => fakeChildProcess.spawnSync('SHELLGUARD_TEST_MARKER'), /blocked/i);
    assert.throws(() => fakeChildProcess.execFileSync('SHELLGUARD_TEST_MARKER'), /blocked/i);
    assert.throws(() => fakeChildProcess.fork('SHELLGUARD_TEST_MARKER'), /blocked/i);
    restoreBlock();
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('hardening snippets are available without writing files', () => {
  const snippets = runtime.hardeningSnippets();
  assert.match(snippets.php_ini, /disable_functions/);
  assert.match(snippets.apache_htaccess, /FilesMatch/);
  assert.match(snippets.nginx, /deny all/);
});
