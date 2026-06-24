/**
 * SecureChat — Frontend JS
 * Handles auth, messaging UI, crypto panel, attack simulations, logs
 */

const socket = io();
let currentUser = null;
let currentContact = null;
let activeTab = 'crypto';
let authMode = 'login';
const avatarColors = ['av-0','av-1','av-2','av-3'];
const avatarMap = {};

// ── Auth ──────────────────────────────────────────────────────────────────────

function setAuthMode(mode) {
  authMode = mode;
  document.getElementById('modal-title').textContent = mode === 'reg' ? 'Register' : 'Sign In';
  document.getElementById('field-name').style.display = mode === 'reg' ? 'block' : 'none';
  document.getElementById('auth-submit').textContent = mode === 'reg' ? 'Register' : 'Sign In';
  document.getElementById('auth-toggle').textContent = mode === 'reg' ? 'Have an account? Sign in' : 'No account? Register';
  document.getElementById('auth-err').style.display = 'none';
  document.getElementById('auth-ok').style.display = 'none';
}

document.getElementById('auth-toggle').onclick = () =>
  setAuthMode(authMode === 'login' ? 'reg' : 'login');

document.getElementById('auth-submit').onclick = async () => {
  const username = document.getElementById('inp-user').value.trim().toLowerCase();
  const password = document.getElementById('inp-pass').value;
  const name = document.getElementById('inp-name').value.trim();
  showAuthErr('');

  if (!username || !password) { showAuthErr('Username and password required.'); return; }

  if (authMode === 'reg') {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ username, password, name })
    });
    const data = await res.json();
    if (!res.ok) { showAuthErr(data.error); return; }
    showAuthOk('Registered! Please sign in.');
    setAuthMode('login');
    document.getElementById('inp-pass').value = '';
    return;
  }

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (!res.ok) { showAuthErr(data.error); return; }

  currentUser = data.username;
  document.getElementById('auth-overlay').style.display = 'none';
  document.getElementById('logged-as').textContent = data.name;
  loadContacts();
};

document.getElementById('inp-pass').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('auth-submit').click();
});
document.getElementById('inp-user').addEventListener('keydown', e => {
  if (e.key === 'Enter') document.getElementById('inp-pass').focus();
});

document.getElementById('logout-btn').onclick = async () => {
  await fetch('/api/logout', { method: 'POST' });
  currentUser = null; currentContact = null;
  document.getElementById('auth-overlay').style.display = 'flex';
  document.getElementById('inp-pass').value = '';
  document.getElementById('auth-err').style.display = 'none';
  document.getElementById('auth-ok').style.display = 'none';
  document.getElementById('contact-list').innerHTML = '';
  document.getElementById('messages').innerHTML = '<div class="empty-state"><div class="empty-icon">💬</div><div>Select a contact to start a secure conversation</div></div>';
};

function showAuthErr(msg) {
  const el = document.getElementById('auth-err');
  if (msg) { el.textContent = msg; el.style.display = 'block'; }
  else { el.style.display = 'none'; }
}
function showAuthOk(msg) {
  const el = document.getElementById('auth-ok');
  el.textContent = msg; el.style.display = 'block';
}

// ── Contacts ──────────────────────────────────────────────────────────────────

async function loadContacts() {
  const res = await fetch('/api/users');
  const users = await res.json();
  const el = document.getElementById('contact-list');
  el.innerHTML = '';
  users.forEach((u, i) => {
    avatarMap[u.username] = avatarColors[i % avatarColors.length];
    const initials = u.name.split(' ').map(w => w[0]).join('').slice(0,2).toUpperCase();
    const div = document.createElement('div');
    div.className = 'contact-item' + (currentContact === u.username ? ' active' : '');
    div.innerHTML = `
      <div class="avatar ${avatarMap[u.username]}">${initials}</div>
      <div>
        <div class="contact-name">${u.name}</div>
        <div class="contact-status"><span class="dot"></span>Online</div>
      </div>
    `;
    div.onclick = () => selectContact(u.username, u.name, initials);
    el.appendChild(div);
  });
}

function selectContact(username, name, initials) {
  currentContact = username;
  document.getElementById('ch-av').textContent = initials;
  document.getElementById('ch-av').className = 'chat-avatar ' + (avatarMap[username] || 'av-0');
  document.getElementById('ch-name').textContent = name;
  loadContacts();
  loadMessages();
  if (activeTab === 'crypto') loadCryptoPanel();
  socket.emit('join', { contact: username });
}

// ── Messages ──────────────────────────────────────────────────────────────────

async function loadMessages() {
  if (!currentContact) return;
  const res = await fetch(`/api/messages/${currentContact}`);
  const msgs = await res.json();
  renderMessages(msgs);
}

function renderMessages(msgs) {
  const el = document.getElementById('messages');
  if (!msgs.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-icon">🔐</div><div>No messages yet — send one!</div></div>';
    return;
  }
  el.innerHTML = '';
  msgs.forEach(m => {
    const mine = m.from === currentUser;
    const row = document.createElement('div');
    row.className = 'msg-row' + (mine ? ' mine' : '');
    const ts = new Date(m.ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    const initials = (m.from[0] || '?').toUpperCase();
    const avClass = avatarMap[m.from] || 'av-0';
    const tampered = m.integrity === 'fail';
    const bubbleClass = tampered ? 'bubble-tampered' : (mine ? 'bubble-out' : 'bubble-in');

    row.innerHTML = `
      ${!mine ? `<div class="msg-av avatar ${avClass}">${initials}</div>` : ''}
      <div>
        <div class="bubble ${bubbleClass}">
          ${tampered ? '⚠️ ' + m.text : m.text}
          <div class="msg-meta">
            ${ts}
            <span class="enc-badge ${tampered ? 'enc-fail' : 'enc-ok'}">${tampered ? '✗ HMAC' : '✓ HMAC'}</span>
            <span class="enc-badge enc-aes">AES-256-GCM</span>
          </div>
        </div>
        ${m.ct_preview ? `<div style="font-size:9px;color:var(--text-3);font-family:monospace;margin-top:2px;padding-left:2px">CT: ${m.ct_preview}</div>` : ''}
      </div>
    `;
    el.appendChild(row);
  });
  el.scrollTop = el.scrollHeight;
}

document.getElementById('send-btn').onclick = sendMessage;
document.getElementById('msg-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const inp = document.getElementById('msg-input');
  const text = inp.value.trim();
  if (!text || !currentContact) return;
  inp.value = '';
  const res = await fetch('/api/send', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ to: currentContact, message: text })
  });
  if (res.ok) {
    loadMessages();
    if (activeTab === 'crypto') loadCryptoPanel();
  }
}

// ── Socket.IO ─────────────────────────────────────────────────────────────────

socket.on('new_message', data => {
  if (currentContact && (data.from === currentContact || data.to === currentContact)) {
    loadMessages();
  }
});

// ── Tabs ──────────────────────────────────────────────────────────────────────

function switchTab(tab) {
  activeTab = tab;
  document.querySelectorAll('.tab').forEach(el =>
    el.classList.toggle('active', el.dataset.tab === tab)
  );
  if (tab === 'crypto') loadCryptoPanel();
  else if (tab === 'attacks') renderAttacks();
  else loadLogs();
}

// ── Crypto Panel ──────────────────────────────────────────────────────────────

async function loadCryptoPanel() {
  const el = document.getElementById('panel-body');
  if (!currentContact) {
    el.innerHTML = '<div class="crypto-idle">Select a contact to see live crypto details</div>';
    return;
  }
  const res = await fetch(`/api/crypto-info/${currentContact}`);
  const info = await res.json();

  el.innerHTML = `
    <div class="section-label">Encryption Algorithm</div>
    <div class="info-row"><span class="info-key">Cipher</span><span class="badge badge-green">${info.algorithm}</span></div>
    <div class="info-row"><span class="info-key">Integrity</span><span class="badge badge-blue">${info.hmac}</span></div>
    <div class="info-row"><span class="info-key">IV Size</span><span class="info-val">${info.iv_length}</span></div>
    <div class="info-row"><span class="info-key">Auth Tag</span><span class="info-val">${info.auth_tag}</span></div>
    <div class="info-row"><span class="info-key">Replay Guard</span><span class="info-val">${info.replay_protection}</span></div>

    <div class="section-label">Key Management</div>
    <div class="info-row"><span class="info-key">Key Exchange</span><span class="info-val">${info.key_exchange}</span></div>
    <div class="info-row"><span class="info-key">Hardcoded Keys?</span><span class="badge badge-green">No — derived</span></div>
    <div class="section-label">Shared Key Fingerprint</div>
    <div class="code-block purple">${info.key_fingerprint}…</div>

    <div class="section-label">Authentication</div>
    <div class="info-row"><span class="info-key">Password Hash</span><span class="badge badge-purple">${info.password_hash}</span></div>
    <div class="info-row"><span class="info-key">Session Token</span><span class="info-val">${info.session_token}</span></div>

    <div class="section-label">Session Stats</div>
    <div class="info-row"><span class="info-key">Messages</span><span class="info-val">${info.message_count}</span></div>
    <div class="info-row"><span class="info-key">With</span><span class="info-val">${currentContact}</span></div>
  `;
}

// ── Attack Simulations ─────────────────────────────────────────────────────────

function renderAttacks() {
  const el = document.getElementById('panel-body');
  el.innerHTML = `
    <div class="section-label">Simulated Attacks</div>
    <button class="attack-btn" onclick="runAttack('mitm')">
      <div class="attack-icon">🕵️</div>
      <div>
        <div class="attack-title">Man-in-the-Middle</div>
        <div class="attack-desc">Intercept and modify a message</div>
      </div>
    </button>
    <button class="attack-btn" onclick="runAttack('replay')">
      <div class="attack-icon">🔁</div>
      <div>
        <div class="attack-title">Replay Attack</div>
        <div class="attack-desc">Re-send a captured packet</div>
      </div>
    </button>
    <button class="attack-btn" onclick="runAttack('bruteforce')">
      <div class="attack-icon">🔓</div>
      <div>
        <div class="attack-title">Brute Force</div>
        <div class="attack-desc">Crack a password via guessing</div>
      </div>
    </button>
    <div id="attack-result" class="result-box">
      Select an attack to simulate. All attacks are blocked by the security system.
    </div>
  `;
}

async function runAttack(type) {
  if (!currentContact && type !== 'bruteforce') {
    document.getElementById('attack-result').innerHTML = '⚠️ Select a contact and send a message first.';
    return;
  }
  const box = document.getElementById('attack-result');
  box.className = 'result-box';
  box.innerHTML = '<div class="loading">⏳ Running simulation…</div>';

  const res = await fetch(`/api/attack/${type}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ contact: currentContact })
  });
  const d = await res.json();

  if (type === 'mitm') {
    box.className = 'result-box ' + (d.detected ? 'result-ok' : 'result-err');
    box.innerHTML = `
      <strong>🕵️ Man-in-the-Middle Simulation</strong><br><br>
      <strong>Step 1:</strong> ${d.step1}<br>
      <strong>Step 2:</strong> ${d.step2}<br>
      <strong>Step 3:</strong> ${d.step3}<br><br>
      <strong>Original CT:</strong> <span style="font-family:monospace;font-size:10px">${d.original_ct}</span><br>
      <strong>Tampered CT:</strong> <span style="font-family:monospace;font-size:10px">${d.tampered_ct}</span><br><br>
      <strong>Result:</strong> ${d.detected ? '✅ Detected & Blocked' : '❌ Not detected'}<br>
      <strong>Reason:</strong> ${d.reason}<br><br>
      <em style="font-size:10px">${d.defense}</em>
    `;
  } else if (type === 'replay') {
    box.className = 'result-box result-ok';
    box.innerHTML = `
      <strong>🔁 Replay Attack Simulation</strong><br><br>
      <strong>Captured nonce:</strong> <span style="font-family:monospace;font-size:10px">${d.captured_nonce.slice(0,16)}…</span><br><br>
      <div class="replay-step step-ok">① ${d.step1}</div>
      <div class="replay-step step-ok">② ${d.step2}</div>
      <div class="replay-step step-blocked">③ ${d.step3}</div><br>
      <strong>Result:</strong> ${d.detected ? '✅ Replay Blocked' : '❌ Not detected'}<br>
      <strong>Reason:</strong> ${d.reason}<br><br>
      <em style="font-size:10px">${d.defense}</em>
    `;
  } else if (type === 'bruteforce') {
    box.className = 'result-box result-ok';
    const rows = d.guesses.map(g =>
      `<div style="font-family:monospace;font-size:10px;padding:2px 0">
        "${g.guess}" → ${g.matched ? '✅ MATCH' : '❌ fail'} (${g.ms}ms)
      </div>`
    ).join('');
    box.innerHTML = `
      <strong>🔓 Brute Force Simulation</strong><br><br>
      <strong>Target:</strong> ${d.target} (bcrypt cost 12)<br>
      <strong>Time:</strong> ${d.total_ms}ms for ${d.guesses.length} guesses<br><br>
      ${rows}<br>
      <strong>SHA-256 rate:</strong> ${d.sha256_rate}<br>
      <strong>bcrypt rate:</strong> ${d.bcrypt_rate}<br><br>
      <em style="font-size:10px">${d.defense}</em>
    `;
  }
}

// ── Logs ──────────────────────────────────────────────────────────────────────

async function loadLogs() {
  const el = document.getElementById('panel-body');
  el.innerHTML = '<div class="loading">Loading logs…</div>';
  const res = await fetch('/api/logs');
  const logs = await res.json();

  const ok = logs.filter(l => l.level === 'INFO').length;
  const warn = logs.filter(l => l.level === 'WARNING').length;
  const err = logs.filter(l => l.level === 'ERROR').length;

  el.innerHTML = `
    <div class="stat-grid">
      <div class="stat-card"><div class="stat-num num-ok">${ok}</div><div class="stat-lbl">OK Events</div></div>
      <div class="stat-card"><div class="stat-num num-warn">${warn}</div><div class="stat-lbl">Warnings</div></div>
      <div class="stat-card"><div class="stat-num num-err">${err}</div><div class="stat-lbl">Errors</div></div>
      <div class="stat-card"><div class="stat-num">${logs.length}</div><div class="stat-lbl">Total</div></div>
    </div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <div class="section-label" style="margin:0">Security Events</div>
      <button onclick="loadLogs()" style="font-size:11px;background:none;border:none;color:var(--text-3);cursor:pointer">↻ Refresh</button>
    </div>
    ${logs.length === 0 ? '<div class="loading">No events yet</div>' : ''}
    ${logs.map(l => `
      <div class="log-entry log-${l.level}">
        [${l.ts}] [${l.type}] ${l.msg}
      </div>
    `).join('')}
  `;
}
