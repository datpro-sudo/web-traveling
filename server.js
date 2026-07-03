const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const USERS_FILE = path.join(__dirname, 'users.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

let users = [];
let sessions = [];

function loadUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, 'utf8');
    users = JSON.parse(data);
  } catch {
    users = [];
  }
}

function saveUsers() {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function loadSessions() {
  try {
    sessions = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
  } catch {
    sessions = [];
  }
}

function saveSessions() {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
}

function createSession(user, rememberMe) {
  const token = crypto.randomBytes(24).toString('hex');
  const expiresAt = Date.now() + (rememberMe ? 1000 * 60 * 60 * 24 * 30 : 1000 * 60 * 60 * 24 * 7);
  sessions.push({ token, userEmail: user.email, expiresAt });
  saveSessions();
  return { token, expiresAt };
}

function getSessionUser(token) {
  if (!token) return null;
  const session = sessions.find(item => item.token === token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions = sessions.filter(item => item.token !== token);
    saveSessions();
    return null;
  }
  const user = users.find(item => item.email === session.userEmail);
  return user || null;
}

function clearSession(token) {
  sessions = sessions.filter(item => item.token !== token);
  saveSessions();
}

loadUsers();
loadSessions();

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml'
};

function readFile(filePath) {
  return fs.promises.readFile(filePath);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      resolve(Object.fromEntries(params.entries()));
    });
    req.on('error', reject);
  });
}

function getJson(res, payload, statusCode = 200) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || '';
  const cookie = cookieHeader.split(';').map(item => item.trim()).find(item => item.startsWith(`${name}=`));
  return cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : null;
}

function setCookie(res, name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge) parts.push(`Max-Age=${options.maxAge}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);
  if (options.secure) parts.push('Secure');
  if (options.path) parts.push(`Path=${options.path}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function sendHtml(res, html, statusCode = 200) {
  res.writeHead(statusCode, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

function sendFile(res, filePath, statusCode = 200) {
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  readFile(filePath)
    .then(content => {
      res.writeHead(statusCode, { 'Content-Type': contentType });
      res.end(content);
    })
    .catch(() => {
      sendHtml(res, '<h1>404 Not Found</h1>', 404);
    });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/') {
    return sendFile(res, path.join(PUBLIC_DIR, 'landing.html'));
  }

  if (req.method === 'GET' && url.pathname === '/login') {
    return sendFile(res, path.join(PUBLIC_DIR, 'login.html'));
  }

  if (req.method === 'GET' && url.pathname === '/register') {
    return sendFile(res, path.join(PUBLIC_DIR, 'register.html'));
  }

  if (req.method === 'GET' && url.pathname === '/styles.css') {
    return sendFile(res, path.join(PUBLIC_DIR, 'styles.css'));
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    return getJson(res, { status: 'ok' });
  }

  if (req.method === 'GET' && url.pathname === '/me') {
    const token = getCookie(req, 'velora_session');
    const user = getSessionUser(token);
    if (!user) return getJson(res, { success: false, message: 'Not authenticated' }, 401);
    return getJson(res, { success: true, user: { email: user.email, fullName: user.fullName, username: user.username } });
  }

  if (req.method === 'POST' && url.pathname === '/logout') {
    const token = getCookie(req, 'velora_session');
    clearSession(token);
    res.setHeader('Set-Cookie', 'velora_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/');
    return getJson(res, { success: true, message: 'Signed out' });
  }

  if (req.method === 'POST' && url.pathname === '/login') {
    const body = await parseBody(req);
    const email = (body.email || '').trim().toLowerCase();
    const password = (body.password || '').trim();
    const rememberMe = body.remember === 'on' || body.remember === 'true';
    const wantsJson = req.headers.accept && req.headers.accept.includes('application/json');

    if (!email || !password) {
      if (wantsJson) return getJson(res, { success: false, message: 'Please enter both email and password.', errors: { modalLoginEmail: !email ? 'Please enter your email.' : '', modalLoginPassword: !password ? 'Please enter your password.' : '' } }, 400);
      return sendHtml(res, '<h1>Missing fields</h1>', 400);
    }

    const matchedUser = users.find(user => user.email === email && user.password === password);

    if (matchedUser) {
      const session = createSession(matchedUser, rememberMe);
      setCookie(res, 'velora_session', session.token, { maxAge: rememberMe ? 60 * 60 * 24 * 30 : 60 * 60 * 24 * 7, httpOnly: true, sameSite: 'Lax', path: '/' });
      if (wantsJson) {
        return getJson(res, { success: true, mode: 'login', user: { email: matchedUser.email, fullName: matchedUser.fullName, username: matchedUser.username }, message: `Welcome back, ${matchedUser.fullName || matchedUser.email}!` });
      }
      return sendHtml(res, '<h1>Logged in</h1>');
    }

    if (wantsJson) return getJson(res, { success: false, message: 'Invalid email or password.' }, 401);
    return sendHtml(res, '<h1>Invalid credentials</h1>', 401);
  }

  if (req.method === 'POST' && url.pathname === '/register') {
    const body = await parseBody(req);
    const fullName = (body.fullName || '').trim();
    const username = (body.username || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    const password = (body.password || '').trim();
    const confirmPassword = (body.confirmPassword || '').trim();
    const wantsJson = req.headers.accept && req.headers.accept.includes('application/json');
    const errors = {};

    if (!fullName) errors.modalFullName = 'Please enter your full name.';
    if (!email) errors.modalRegisterEmail = 'Please enter your email.';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.modalRegisterEmail = 'Please enter a valid email.';
    if (!password) errors.modalRegisterPassword = 'Please create a password.';
    else if (password.length < 8) errors.modalRegisterPassword = 'Use at least 8 characters.';
    if (!confirmPassword) errors.modalConfirmPassword = 'Please confirm your password.';
    else if (password && password !== confirmPassword) errors.modalConfirmPassword = 'Passwords do not match.';

    const exists = users.some(user => user.email === email);
    if (exists) errors.modalRegisterEmail = 'This email is already in use.';

    if (Object.keys(errors).length) {
      if (wantsJson) return getJson(res, { success: false, message: 'Please fix the highlighted errors.', errors }, 400);
      return sendHtml(res, '<h1>Validation failed</h1>', 400);
    }

    const newUser = { fullName, username: username || fullName.replace(/\s+/g, '').toLowerCase(), email, password };
    users.push(newUser);
    saveUsers();

    const rememberMe = body.remember === 'on' || body.remember === 'true';
    const session = createSession(newUser, rememberMe);
    setCookie(res, 'velora_session', session.token, { maxAge: rememberMe ? 60 * 60 * 24 * 30 : 60 * 60 * 24 * 7, httpOnly: true, sameSite: 'Lax', path: '/' });

    if (wantsJson) return getJson(res, { success: true, mode: 'register', user: { email: newUser.email, fullName: newUser.fullName, username: newUser.username }, message: `Welcome aboard, ${newUser.fullName}!` });
    return sendHtml(res, '<h1>Account created</h1>');
  }

  sendHtml(res, '<h1>404 Not Found</h1>', 404);
});

let currentPort = Number(PORT);

function startServer(port) {
  currentPort = port;
  server.listen(port, () => {
    console.log(`Login demo server is running on http://localhost:${port}`);
  });
}

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    const nextPort = currentPort + 1;
    if (nextPort > currentPort + 10) {
      console.error(`Unable to start the server after trying ports ${currentPort} to ${nextPort - 1}`);
      process.exit(1);
    }

    console.warn(`Port ${currentPort} is busy. Trying ${nextPort} instead...`);
    startServer(nextPort);
  } else {
    throw err;
  }
});

startServer(currentPort);
