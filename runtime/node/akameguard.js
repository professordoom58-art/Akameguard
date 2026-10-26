'use strict';

/**
 * AkameGuard Node.js runtime protection.
 *
 * The default mode is MONITOR: matching requests are logged and passed to the
 * application. BLOCK mode is opt-in. This module never evaluates request data
 * and never turns request strings into code or shell commands.
 *
 * Express-style installation:
 *   app.use(require('./akameguard').createMiddleware());
 *
 * Plain http installation:
 *   const guard = require('./akameguard').createMiddleware();
 *   http.createServer((req, res) => guard(req, res, () => handler(req, res)));
 */

const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const url = require('url');

const DEFAULT_CONFIG_PATH = path.join(__dirname, 'config.json');
const DEFAULT_RULES_PATH = path.join(__dirname, 'rules.json');
const SCRIPT_EXTENSIONS = new Set(['.php', '.phtml', '.php5', '.phar', '.js', '.mjs', '.cjs']);
const UPLOAD_FOLDER_NAMES = new Set(['upload', 'uploads', 'uploaded', 'media', 'attachments']);
let processDefaultLogPath;

function defaultLogPath() {
  if (!processDefaultLogPath) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'akameguard-'));
    if (process.platform !== 'win32') fs.chmodSync(directory, 0o700);
    processDefaultLogPath = path.join(directory, 'runtime.jsonl');
  }
  return processDefaultLogPath;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_error) {
    return fallback;
  }
}

function mergeConfig(base, override) {
  const result = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value) && result[key] && typeof result[key] === 'object' && !Array.isArray(result[key])) {
      result[key] = mergeConfig(result[key], value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

function resolveConfiguredPath(value, baseDir) {
  if (!value) return '';
  return path.isAbsolute(value) ? value : path.resolve(baseDir, value);
}

function loadConfig(options = {}) {
  const configPath = path.resolve(options.configPath || DEFAULT_CONFIG_PATH);
  const fileConfig = readJson(configPath, {});
  const defaults = {
    mode: 'monitor',
    log_path: '',
    rules_path: 'rules.json',
    baseline_path: '',
    web_root: '',
    ip_allowlist: [],
    path_allowlist: [],
    uploads_folders: ['upload', 'uploads', 'uploaded', 'media', 'attachments'],
    child_process_guard: {
      enabled: false,
      mode: 'monitor',
      allowlist: [],
    },
  };
  const aliases = {
    mode: options.mode,
    log_path: options.logPath,
    rules_path: options.rulesPath,
    baseline_path: options.baselinePath,
    web_root: options.webRoot,
    ip_allowlist: options.ipAllowlist,
    path_allowlist: options.pathAllowlist,
    uploads_folders: options.uploadsFolders,
  };
  const definedAliases = Object.fromEntries(Object.entries(aliases).filter(([, value]) => value !== undefined));
  const config = mergeConfig(defaults, mergeConfig(fileConfig, definedAliases));
  config.mode = String(config.mode).toLowerCase() === 'block' ? 'block' : 'monitor';
  config._configPath = configPath;
  config._configDir = path.dirname(configPath);
  config.rulesPath = resolveConfiguredPath(config.rules_path, config._configDir) || DEFAULT_RULES_PATH;
  config.baselinePath = resolveConfiguredPath(config.baseline_path, config._configDir);
  config.logPath = resolveConfiguredPath(config.log_path, config._configDir) || defaultLogPath();
  config.webRoot = config.web_root
    ? resolveConfiguredPath(config.web_root, config._configDir)
    : (options.webRoot || process.cwd());
  config.ipAllowlist = Array.isArray(config.ip_allowlist) ? config.ip_allowlist.map(String) : [];
  config.pathAllowlist = Array.isArray(config.path_allowlist) ? config.path_allowlist.map(String) : [];
  config.uploadsFolders = Array.isArray(config.uploads_folders)
    ? config.uploads_folders.map((item) => String(item).toLowerCase())
    : Array.from(UPLOAD_FOLDER_NAMES);
  config.childProcessGuard = config.child_process_guard || {};
  if (config.ipAllowlist.includes('*')) {
    console.warn('AkameGuard warning: ip_allowlist contains "*" and bypasses request inspection for every client.');
  }
  if (config.pathAllowlist.includes('/*')) {
    console.warn('AkameGuard warning: path_allowlist contains "/*" and bypasses request inspection for every path.');
  }
  return config;
}

function loadRules(config) {
  const rules = readJson(config.rulesPath || DEFAULT_RULES_PATH, {});
  return Array.isArray(rules.request_patterns) ? rules.request_patterns : [];
}

function compileRegex(pattern) {
  if (!pattern) return null;
  try {
    return new RegExp(pattern, 'i');
  } catch (_error) {
    return null;
  }
}

function compileRules(rules) {
  return rules.map((rule) => {
    if (!rule || typeof rule !== 'object') return rule;
    return {
      ...rule,
      _compiled: true,
      _parameterRegex: compileRegex(rule.parameter_regex),
      _valueRegex: compileRegex(rule.regex),
    };
  });
}

function ensureCompiledRules(rules) {
  return Array.isArray(rules) && rules.every((rule) => !rule || rule._compiled)
    ? rules
    : compileRules(rules || []);
}

function logEvent(config, event) {
  const record = {
    timestamp: new Date().toISOString(),
    runtime: 'node',
    ...event,
  };
  try {
    const descriptor = fs.openSync(config.logPath, 'a', 0o600);
    try {
      if (process.platform !== 'win32') fs.fchmodSync(descriptor, 0o600);
      fs.writeSync(descriptor, `${JSON.stringify(record)}\n`, null, 'utf8');
    } finally {
      fs.closeSync(descriptor);
    }
  } catch (_error) {
    // Runtime logging must not turn monitor mode into an application outage.
  }
}

function requestPath(req) {
  const raw = String(req.url || '/');
  try {
    return new url.URL(raw, 'http://akameguard.local').pathname || '/';
  } catch (_error) {
    return '/';
  }
}

function requestIp(req) {
  return String((req.socket && req.socket.remoteAddress) || (req.connection && req.connection.remoteAddress) || 'unknown');
}

function pathAllowed(requestedPath, config) {
  const normalized = `/${String(requestedPath).replace(/^[\\/]+/, '')}`;
  return config.pathAllowlist.some((allowedValue) => {
    const allowed = `/${String(allowedValue).replace(/^[\\/]+/, '')}`;
    return allowed === '/*' || allowed === normalized || (allowed.endsWith('*') && normalized.startsWith(allowed.slice(0, -1)));
  });
}

function ipToBytes(value) {
  const version = net.isIP(value);
  if (version === 4) {
    return Buffer.from(value.split('.').map((part) => Number(part)));
  }
  if (version !== 6) return null;

  let normalized = String(value).toLowerCase();
  const lastColon = normalized.lastIndexOf(':');
  const ipv4Tail = normalized.slice(lastColon + 1);
  if (ipv4Tail.includes('.')) {
    const octets = ipv4Tail.split('.').map((part) => Number(part));
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    normalized = `${normalized.slice(0, lastColon + 1)}${high}:${low}`;
  }

  const sections = normalized.split('::');
  if (sections.length > 2) return null;
  const left = sections[0] ? sections[0].split(':') : [];
  const right = sections.length === 2 && sections[1] ? sections[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (sections.length === 1 && missing !== 0) return null;
  if (sections.length === 2 && missing < 1) return null;
  const groups = sections.length === 2
    ? [...left, ...Array(missing).fill('0'), ...right]
    : left;
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return null;

  const bytes = Buffer.alloc(16);
  groups.forEach((group, index) => bytes.writeUInt16BE(parseInt(group, 16), index * 2));
  return bytes;
}

function cidrMatches(ip, cidr) {
  const separator = String(cidr).indexOf('/');
  if (separator < 1) return false;
  const network = String(cidr).slice(0, separator);
  const bits = Number(String(cidr).slice(separator + 1));
  const addressBytes = ipToBytes(ip);
  const networkBytes = ipToBytes(network);
  if (
    !addressBytes
    || !networkBytes
    || addressBytes.length !== networkBytes.length
    || !Number.isInteger(bits)
    || bits < 0
    || bits > addressBytes.length * 8
  ) {
    return false;
  }
  const wholeBytes = Math.floor(bits / 8);
  if (!addressBytes.subarray(0, wholeBytes).equals(networkBytes.subarray(0, wholeBytes))) {
    return false;
  }
  const remainder = bits % 8;
  if (remainder === 0) return true;
  const mask = (0xff << (8 - remainder)) & 0xff;
  return (addressBytes[wholeBytes] & mask) === (networkBytes[wholeBytes] & mask);
}

function ipAllowed(ip, config) {
  return config.ipAllowlist.some((allowedValue) => {
    const allowed = String(allowedValue);
    return allowed === '*' || allowed === ip || cidrMatches(ip, allowed);
  });
}

function isUploadsPath(requestedPath, config) {
  return String(requestedPath)
    .split('/')
    .some((part) => config.uploadsFolders.includes(part.toLowerCase()) || part.toLowerCase().startsWith('upload'));
}

function isScriptPath(requestedPath) {
  return SCRIPT_EXTENSIONS.has(path.extname(requestedPath).toLowerCase());
}

function isNewBaselineFile(requestedPath, config) {
  if (!config.baselinePath || !config.webRoot) return false;
  let decoded;
  try {
    decoded = decodeURIComponent(String(requestedPath));
  } catch (_error) {
    return false;
  }
  if (decoded.includes('\0') || decoded.split('/').includes('..')) return false;
  const root = path.resolve(config.webRoot);
  const candidate = path.resolve(root, `.${decoded.startsWith('/') ? decoded : `/${decoded}`}`);
  if (!candidate.startsWith(`${root}${path.sep}`) || !fs.existsSync(candidate)) return false;
  let stat;
  try {
    stat = fs.statSync(candidate);
  } catch (_error) {
    return false;
  }
  if (!stat.isFile()) return false;
  const baseline = readJson(config.baselinePath, {});
  return !((baseline.files || []).some((record) => record && record.path === path.relative(root, candidate).split(path.sep).join('/')));
}

function flattenValues(value, key, output, depth = 0) {
  if (depth > 8 || value === null || value === undefined) return;
  if (Array.isArray(value)) {
    value.forEach((item, index) => flattenValues(item, `${key}.${index}`, output, depth + 1));
    return;
  }
  if (typeof value === 'object') {
    Object.entries(value).forEach(([childKey, childValue]) => flattenValues(childValue, `${key}.${childKey}`, output, depth + 1));
    return;
  }
  output.push({ key, value: String(value) });
}

function decodeRequestValue(value) {
  let decoded = String(value);
  for (let layer = 0; layer < 2; layer += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch (_error) {
      break;
    }
  }
  return decoded;
}

function requestValues(req) {
  const values = [];
  try {
    const parsed = new url.URL(String(req.url || '/'), 'http://akameguard.local');
    parsed.searchParams.forEach((value, key) => values.push({ key: `query.${key}`, value }));
  } catch (_error) {
    // A malformed URL is not a reason to execute or reject application code.
  }
  flattenValues(req.query, 'query', values);
  flattenValues(req.body, 'body', values);
  flattenValues(req.params, 'params', values);
  flattenValues(req.cookies, 'cookies', values);
  flattenValues(req.headers, 'header', values);
  return values.map((item) => ({ ...item, value: decodeRequestValue(item.value) }));
}

function parameterName(key) {
  const pieces = String(key).split('.');
  return pieces[pieces.length - 1].toLowerCase();
}

function regexMatches(pattern, value) {
  return Boolean(pattern && typeof pattern.test === 'function' && pattern.test(value));
}

function inspectRequest(req, config, rules = loadRules(config)) {
  const currentPath = requestPath(req);
  const ip = requestIp(req);
  if (ipAllowed(ip, config) || pathAllowed(currentPath, config)) return [];
  const events = [];
  for (const rule of ensureCompiledRules(rules)) {
    if (!rule || typeof rule !== 'object') continue;
    for (const item of requestValues(req)) {
      const parameterMatches = !rule._parameterRegex || regexMatches(rule._parameterRegex, parameterName(item.key));
      if (parameterMatches && regexMatches(rule._valueRegex, item.value)) {
        events.push({
          type: 'request_pattern',
          rule_id: String(rule.id || 'unknown'),
          severity: String(rule.severity || 'medium'),
          explanation: String(rule.description || 'Shared runtime request rule matched.'),
          path: currentPath,
          parameter: item.key,
          ip,
          mode: config.mode,
        });
        break;
      }
    }
  }
  if (isUploadsPath(currentPath, config) && isScriptPath(currentPath)) {
    events.push({
      type: 'uploads_execution',
      rule_id: 'RUNTIME-UPLOADS-SCRIPT',
      severity: 'high',
      explanation: 'A script execution request targeted an uploads-style path.',
      path: currentPath,
      ip,
      mode: config.mode,
    });
  }
  if (isNewBaselineFile(currentPath, config)) {
    events.push({
      type: 'baseline_new_file',
      rule_id: 'RUNTIME-BASELINE-NEW',
      severity: isScriptPath(currentPath) || isUploadsPath(currentPath, config) ? 'high' : 'low',
      explanation: 'The requested file is not present in the configured baseline.',
      path: currentPath,
      ip,
      mode: config.mode,
    });
  }
  return events;
}

function blockResponse(res) {
  res.statusCode = 403;
  if (typeof res.setHeader === 'function') res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('Request blocked by AkameGuard.\n');
}

function createMiddleware(options = {}) {
  const config = loadConfig(options);
  const rules = compileRules(loadRules(config));
  if (config.childProcessGuard && config.childProcessGuard.enabled) {
    installChildProcessGuard({
      ...config.childProcessGuard,
      mode: config.childProcessGuard.mode || config.mode,
      logPath: config.logPath,
    });
  }
  return function akameguardMiddleware(req, res, next) {
    const events = inspectRequest(req, config, rules);
    events.forEach((event) => logEvent(config, event));
    if (events.length > 0 && config.mode === 'block') {
      blockResponse(res);
      return false;
    }
    if (typeof next === 'function') next();
    return true;
  };
}

function wrapRequestHandler(handler, options = {}) {
  const middleware = createMiddleware(options);
  return (req, res) => middleware(req, res, () => handler(req, res));
}

function commandFromCall(name, args) {
  const command = String(args[0] || '');
  if (name === 'spawn' || name === 'spawnSync') return command;
  return command;
}

function commandAllowed(command, allowlist) {
  const text = String(command).trim();
  const firstToken = text.split(/\s+/, 1)[0];
  const base = path.basename(firstToken);
  return allowlist.some((item) => String(item) === text || String(item) === firstToken || String(item) === base);
}

function installChildProcessGuard(options = {}) {
  const childProcess = options.childProcess || require('child_process');
  const mode = options.strict || String(options.mode || 'monitor').toLowerCase() === 'block' ? 'block' : 'monitor';
  const allowlist = Array.isArray(options.allowlist) ? options.allowlist.map(String) : [];
  const logPath = options.logPath || defaultLogPath();
  const names = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'];
  const originals = {};
  for (const name of names) {
    if (typeof childProcess[name] !== 'function') continue;
    originals[name] = childProcess[name];
    childProcess[name] = function guardedChildProcessCall(...args) {
      const command = commandFromCall(name, args);
      if (commandAllowed(command, allowlist)) return originals[name].apply(this, args);
      const event = {
        type: 'child_process_call',
        rule_id: 'RUNTIME-CHILD-PROCESS',
        severity: 'high',
        operation: name,
        command: command.slice(0, 120),
        mode,
      };
      logEvent({ logPath }, event);
      if (mode === 'block') {
        const error = new Error('AkameGuard blocked a child_process call.');
        if (['exec', 'execFile'].includes(name) && typeof args[args.length - 1] === 'function') {
          args[args.length - 1](error);
          return undefined;
        }
        throw error;
      }
      return originals[name].apply(this, args);
    };
  }
  return function restoreChildProcessGuard() {
    for (const [name, original] of Object.entries(originals)) childProcess[name] = original;
  };
}

function hardeningSnippets() {
  return {
    php_ini: 'disable_functions = exec,system,shell_exec,passthru,proc_open,popen',
    apache_htaccess: '<FilesMatch "\\.(?i:php|phtml|php5|phar)$">\n    Require all denied\n</FilesMatch>',
    nginx: 'location ~* ^/(?:upload|uploads|uploaded|media|attachments)/.*\\.(?:php|phtml|php5|phar)$ {\n    deny all;\n}',
  };
}

module.exports = {
  createMiddleware,
  wrapRequestHandler,
  inspectRequest,
  installChildProcessGuard,
  hardeningSnippets,
  loadConfig,
  loadRules,
};
