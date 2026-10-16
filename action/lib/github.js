'use strict';

// Small helpers shared by the action scripts: a GitHub REST client built on
// Node's own https module, workflow command output, and event payload
// reading. No npm dependencies, and nothing newer than Node 14 so the action
// works whatever Node version the workflow has set up.

const fs = require('fs');
const https = require('https');
const http = require('http');
const { URL } = require('url');

function env(name, fallback) {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : value;
}

function bool(name, fallback) {
  const value = env(name, '');
  if (value === '') return fallback;
  return /^(true|1|yes|on)$/i.test(value.trim());
}

// Workflow commands. Messages are escaped the way the runner expects so a
// stray newline or percent sign cannot break out of the annotation.
function escapeCommand(text) {
  return String(text).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}
function notice(message) {
  console.log('::notice::' + escapeCommand(message));
}
function warning(message) {
  console.log('::warning::' + escapeCommand(message));
}

// Append a step output. Multi-line values use the heredoc form with a random
// delimiter so the value cannot end the block early.
function setOutput(name, value) {
  const file = env('GITHUB_OUTPUT', '');
  const text = value === undefined || value === null ? '' : String(value);
  if (!file) {
    console.log('[output] ' + name + '=' + text);
    return;
  }
  const delimiter = 'DR_EOF_' + Math.random().toString(36).slice(2);
  fs.appendFileSync(file, name + '<<' + delimiter + '\n' + text + '\n' + delimiter + '\n');
}

function readEvent() {
  const file = env('GITHUB_EVENT_PATH', '');
  if (!file || !fs.existsSync(file)) return {};
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    warning('Could not read the event payload: ' + err.message);
    return {};
  }
}

class GitHubError extends Error {
  constructor(status, method, path, body) {
    const detail = body && body.message ? ': ' + body.message : '';
    super(method + ' ' + path + ' returned ' + status + detail);
    this.status = status;
    this.body = body;
  }
}

// Returns a function `request(method, path, body)` that resolves with the
// parsed JSON response, or rejects with a GitHubError for any non-2xx status.
function createClient(token, apiUrl) {
  const base = new URL((apiUrl || 'https://api.github.com').replace(/\/+$/, '') + '/');

  return function request(method, path, body) {
    const url = new URL(path.replace(/^\/+/, ''), base);
    const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
    const headers = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'dependency-radar-action',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (token) headers.Authorization = 'Bearer ' + token;
    if (payload) {
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(payload.length);
    }
    const transport = url.protocol === 'http:' ? http : https;

    return new Promise((resolve, reject) => {
      const req = transport.request(url, { method, headers, timeout: 30000 }, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed = null;
          if (text) {
            try {
              parsed = JSON.parse(text);
            } catch (err) {
              parsed = { message: text.slice(0, 200) };
            }
          }
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
          else reject(new GitHubError(res.statusCode, method, url.pathname, parsed));
        });
      });
      req.on('timeout', () => req.destroy(new Error(method + ' ' + url.pathname + ' timed out')));
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  };
}

module.exports = {
  env,
  bool,
  notice,
  warning,
  setOutput,
  readEvent,
  createClient,
  GitHubError,
};
