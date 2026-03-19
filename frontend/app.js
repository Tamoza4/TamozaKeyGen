/**
 * app.js — TamozaKeyGen Admin Dashboard
 *
 * Responsibilities:
 *  - Dark mode toggle with localStorage persistence
 *  - Fetch + render stats (Total, Active, Suspended, Suspicious)
 *  - Fetch + render license key table with live search
 *  - Action handlers: Reset HWID, Toggle HWID Lock, Pause/Resume, Extend Time
 *  - Forensic View modal: full login history, device info, activity metrics
 *  - Toast notification system
 *
 * API base: /api/v1/admin — all requests attach Authorization: Bearer <token>
 * Auth token is read from localStorage key "adminToken".
 */

'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE = '/api/v1/admin';
const TOKEN_KEY = 'adminToken';

// ─────────────────────────────────────────────────────────────────────────────
// XSS Protection — escape all user-sourced strings before DOM insertion
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Escapes a value for safe insertion into an HTML context.
 * @param {*} val
 * @returns {string}
 */
function esc(val) {
  if (val === null || val === undefined) return '—';
  const node = document.createElement('span');
  node.appendChild(document.createTextNode(String(val)));
  return node.innerHTML;
}

// ─────────────────────────────────────────────────────────────────────────────
// API Helper
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Authenticated fetch wrapper.
 * @param {string} path   - Path relative to API_BASE
 * @param {object} [opts] - Standard fetch options (method, body, etc.)
 * @returns {Promise<any>} Parsed JSON response
 * @throws {Error} On non-2xx status or network failure
 */
async function apiFetch(path, opts = {}) {
  const token = localStorage.getItem(TOKEN_KEY) ?? '';
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...(opts.headers ?? {}),
    },
    ...opts,
  });

  if (!response.ok) {
    // Expired / invalid token → send back to login
    if (response.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = 'index.html';
      return;
    }
    let detail = `HTTP ${response.status}`;
    try {
      const err = await response.json();
      detail = err.detail ?? detail;
    } catch (_) { /* ignore JSON parse failure */ }
    throw new Error(detail);
  }

  // 204 No Content — return null
  if (response.status === 204) return null;
  return response.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Toast Notifications
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Show a non-blocking toast message.
 * @param {string} message
 * @param {'success'|'error'|'info'|'warning'} type
 */
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');

  const colours = {
    success: 'bg-emerald-600',
    error:   'bg-red-600',
    warning: 'bg-amber-500',
    info:    'bg-indigo-600',
  };

  const icons = {
    success: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>',
    error:   '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9.303 3.376c.866 1.5-.217 3.374-1.948 3.374H4.645c-1.73 0-2.813-1.874-1.948-3.374l7.551-13.021c.866-1.5 3.032-1.5 3.898 0L20.303 16.126zM12 15.75h.007v.008H12v-.008z"/>',
    warning: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9.303 3.376c.866 1.5-.217 3.374-1.948 3.374H4.645c-1.73 0-2.813-1.874-1.948-3.374l7.551-13.021c.866-1.5 3.032-1.5 3.898 0L20.303 16.126zM12 15.75h.007v.008H12v-.008z"/>',
    info:    '<path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/>',
  };

  const toast = document.createElement('div');
  toast.className = `toast flex items-center gap-3 px-4 py-3 rounded-xl shadow-lg text-white text-xs font-medium pointer-events-auto max-w-xs ${colours[type] ?? colours.info}`;
  toast.innerHTML = `
    <svg class="w-4 h-4 flex-shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
      ${icons[type] ?? icons.info}
    </svg>
    <span>${esc(message)}</span>
  `;

  container.appendChild(toast);

  // Auto-remove after 4 s with a fade-out
  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s';
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Dark Mode
// ─────────────────────────────────────────────────────────────────────────────

function initDarkMode() {
  const saved = localStorage.getItem('theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const dark = saved === 'dark' || (!saved && prefersDark);
  applyDarkMode(dark);
}

function applyDarkMode(dark) {
  document.documentElement.classList.toggle('dark', dark);
  document.getElementById('iconSun').classList.toggle('hidden', !dark);
  document.getElementById('iconMoon').classList.toggle('hidden', dark);
}

function toggleDarkMode() {
  const isDark = document.documentElement.classList.toggle('dark');
  localStorage.setItem('theme', isDark ? 'dark' : 'light');
  document.getElementById('iconSun').classList.toggle('hidden', !isDark);
  document.getElementById('iconMoon').classList.toggle('hidden', isDark);
}

// ─────────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────────

async function loadStats() {
  try {
    const data = await apiFetch('/stats');
    document.getElementById('stat-total').textContent      = data.total       ?? 0;
    document.getElementById('stat-active').textContent     = data.active      ?? 0;
    document.getElementById('stat-expired').textContent    = data.expired     ?? 0;
    document.getElementById('stat-suspended').textContent  = data.suspended   ?? 0;
    document.getElementById('stat-suspicious').textContent = data.suspicious  ?? 0;
    document.getElementById('stat-online').textContent     = data.online      ?? 0;
    await loadAlerts();
  } catch (err) {
    console.error('[Stats]', err.message);
  }
}

// ────────────────────────────────────────────────────────────────────────────────
// Alerts
// ────────────────────────────────────────────────────────────────────────────────

async function loadAlerts() {
  try {
    const data = await apiFetch('/alerts');
    renderAlerts(data.alerts ?? []);
  } catch (_) { /* non-critical */ }
}

function renderAlerts(alerts) {
  const section = document.getElementById('alertsSection');
  const list    = document.getElementById('alertsList');

  // Filter out the "all clear" info message — only show actual warnings/errors
  const actionable = alerts.filter(a => a.level !== 'info');

  if (actionable.length === 0) {
    section.classList.add('hidden');
    return;
  }

  section.classList.remove('hidden');

  const levelCls = {
    danger:  'bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400',
    warning: 'bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-400',
    info:    'bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-400',
  };

  const frag = document.createDocumentFragment();
  actionable.forEach(alert => {
    const div = document.createElement('div');
    div.className = `flex items-start gap-3 px-4 py-3 rounded-xl text-xs font-medium ${levelCls[alert.level] ?? levelCls.info}`;
    const icon = document.createElement('svg');
    icon.setAttribute('class', 'w-4 h-4 flex-shrink-0 mt-0.5');
    icon.setAttribute('fill', 'none');
    icon.setAttribute('stroke', 'currentColor');
    icon.setAttribute('stroke-width', '2');
    icon.setAttribute('viewBox', '0 0 24 24');
    icon.innerHTML = alert.level === 'danger' || alert.level === 'warning'
      ? '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>'
      : '<path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/>';
    const span = document.createElement('span');
    span.textContent = alert.message;
    div.append(icon, span);
    frag.appendChild(div);
  });

  list.replaceChildren(frag);
}

// ─────────────────────────────────────────────────────────────────────────────
// Keys Table
// ─────────────────────────────────────────────────────────────────────────────

/** @type {Array<object>} Full key list kept in memory for client-side search */
let allKeys = [];

// Active filter state
let _filterStatus  = '';
let _filterApp     = '';
let _filterClass   = '';
let _forensicKeyId   = null;
let _forensicData    = null;   // Cached forensic API response
let _forensicEditMode = false; // Whether the Forensic modal is in edit mode

async function loadKeys() {
  try {
    const data = await apiFetch('/keys');
    allKeys = Array.isArray(data) ? data : (data.keys ?? []);

    // Populate app filter dropdown dynamically
    const appFilter  = document.getElementById('filterApp');
    const prevApp    = appFilter.value;
    const apps = [...new Set(allKeys.map(k => k.app_name).filter(Boolean))].sort();
    while (appFilter.options.length > 1) appFilter.remove(1);
    apps.forEach(app => {
      const opt = document.createElement('option');
      opt.value       = app;
      opt.textContent = app;
      appFilter.appendChild(opt);
    });
    if (apps.includes(prevApp)) appFilter.value = prevApp;

    applyFiltersAndSearch();
  } catch (err) {
    renderErrorRow(err.message);
  }
}

/**
 * Renders the key table from an array. Uses DOM methods for user-sourced data.
 * @param {Array<object>} keys
 */
function renderTable(keys) {
  const tbody = document.getElementById('keysBody');
  const badge  = document.getElementById('rowCountBadge');

  badge.textContent = `${keys.length} key${keys.length !== 1 ? 's' : ''}`;
  badge.classList.remove('hidden');

  if (keys.length === 0) {
    tbody.innerHTML = `
      <tr><td colspan="9" class="text-center py-12 text-gray-400 dark:text-gray-500">
        No keys match your search.
      </td></tr>`;
    return;
  }

  // Build all rows as a document fragment — avoids repeated reflows
  const frag = document.createDocumentFragment();
  keys.forEach(key => frag.appendChild(buildRow(key)));
  tbody.replaceChildren(frag);
}

function renderErrorRow(msg) {
  const tbody = document.getElementById('keysBody');
  const tr = document.createElement('tr');
  const td = document.createElement('td');
  td.colSpan = 9;
  td.className = 'text-center py-12 text-red-500 dark:text-red-400';
  td.textContent = `Failed to load keys: ${msg}`;
  tr.appendChild(td);
  tbody.replaceChildren(tr);
}

/**
 * Builds a single <tr> element for a license key.
 * All variable data set via .textContent — no XSS risk.
 * @param {object} key
 * @returns {HTMLTableRowElement}
 */
function buildRow(key) {
  const now = new Date();
  const expired = key.end_date && new Date(key.end_date) < now;
  const status  = key.is_paused ? 'paused' : (expired ? 'expired' : 'active');

  const statusClasses = {
    active:  'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-400',
    paused:  'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-400',
    expired: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-500',
  };

  const tr = document.createElement('tr');
  tr.className = 'text-gray-700 dark:text-gray-300';
  tr.dataset.id = key.id;

  // Helper: create a <td> with optional extra classes
  const td = (cls = '') => {
    const el = document.createElement('td');
    el.className = `px-4 py-3 ${cls}`;
    return el;
  };

  // ── Key String (truncated + copy button) ──
  const tdKey = td('font-mono');
  const keyWrap = document.createElement('div');
  keyWrap.className = 'flex items-center gap-2';

  const keySpan = document.createElement('span');
  keySpan.className = 'truncate max-w-[140px] inline-block align-middle';
  keySpan.title = key.key_string;
  keySpan.textContent = key.key_string;

  const copyBtn = document.createElement('button');
  copyBtn.title = 'Copy key';
  copyBtn.className = 'flex-shrink-0 text-gray-400 hover:text-indigo-500 transition';
  copyBtn.innerHTML = `<svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" d="M15.666 3.888A2.25 2.25 0 0013.5 2.25h-3c-1.03 0-1.9.693-2.166 1.638m7.332 0c.055.194.084.4.084.612v0a.75.75 0 01-.75.75H9a.75.75 0 01-.75-.75v0c0-.212.03-.418.084-.612m7.332 0c.646.049 1.288.11 1.927.184 1.1.128 1.907 1.077 1.907 2.185V19.5a2.25 2.25 0 01-2.25 2.25H6.75A2.25 2.25 0 014.5 19.5V6.257c0-1.108.806-2.057 1.907-2.185a48.208 48.208 0 011.927-.184"/>
  </svg>`;
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(key.key_string).then(() => showToast('Key copied to clipboard.', 'success'));
  });

  // Suspicious flag
  if (key.is_suspicious) {
    const flag = document.createElement('span');
    flag.title = 'Marked as suspicious';
    flag.innerHTML = `<svg class="w-3 h-3 text-red-500" fill="currentColor" viewBox="0 0 24 24">
      <path fill-rule="evenodd" d="M9.401 3.003c1.155-2 4.043-2 5.197 0l7.355 12.748c1.154 2-.29 4.5-2.599 4.5H4.645c-2.309 0-3.752-2.5-2.598-4.5L9.4 3.003zM12 8.25a.75.75 0 01.75.75v3.75a.75.75 0 01-1.5 0V9a.75.75 0 01.75-.75zm0 8.25a.75.75 0 100-1.5.75.75 0 000 1.5z" clip-rule="evenodd"/>
    </svg>`;
    keyWrap.appendChild(flag);
  }

  keyWrap.appendChild(keySpan);
  keyWrap.appendChild(copyBtn);
  tdKey.appendChild(keyWrap);

  // ── App / Owner ──
  const tdApp = td();
  const appDiv = document.createElement('div');
  appDiv.className = 'font-medium text-gray-900 dark:text-gray-100';
  appDiv.textContent = key.app_name ?? '—';
  const ownerDiv = document.createElement('div');
  ownerDiv.className = 'text-gray-400 mt-0.5';
  ownerDiv.textContent = key.owner_name ?? '—';
  tdApp.append(appDiv, ownerDiv);

  // ── Class / Permission ──
  const tdClass = td();
  const classDiv = document.createElement('div');
  classDiv.className = 'font-medium text-gray-900 dark:text-gray-100';
  classDiv.textContent = key.key_class ?? '—';
  const permDiv = document.createElement('div');
  permDiv.className = 'text-gray-400 mt-0.5';
  permDiv.textContent = key.permission_level ?? '—';
  tdClass.append(classDiv, permDiv);

  // ── Status Badge ──
  const tdStatus = td();
  const badge = document.createElement('span');
  badge.className = `inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide ${statusClasses[status]}`;
  badge.textContent = status;
  tdStatus.appendChild(badge);

  // Append online dot if active
  if (key.is_online && status === 'active') {
    const onlineDot = document.createElement('span');
    onlineDot.className = 'ml-1.5 inline-block w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse';
    onlineDot.title = 'Currently online';
    tdStatus.appendChild(onlineDot);
  }

  // ── HWID Lock ──
  const tdHwid = td();
  const hwidBadge = document.createElement('span');
  const hwidEnabled = key.hwid_lock_enabled;
  hwidBadge.className = `inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold ${
    hwidEnabled
      ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-400'
      : 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-500'
  }`;
  hwidBadge.textContent = hwidEnabled ? 'Locked' : 'Off';
  tdHwid.appendChild(hwidBadge);

  // ── Devices ──
  const tdDevices = td('tabular-nums');
  tdDevices.textContent = `${key.current_devices ?? 0} / ${key.max_devices ?? 1}`;

  // ── Last IP / Region ──
  const tdIp = td();
  const ipDiv = document.createElement('div');
  ipDiv.className = 'font-mono text-gray-700 dark:text-gray-300';
  ipDiv.textContent = key.last_ip ?? '—';
  const regionDiv = document.createElement('div');
  regionDiv.className = 'text-gray-400 mt-0.5';
  regionDiv.textContent = key.last_region ?? '—';
  tdIp.append(ipDiv, regionDiv);

  // ── Expires ──
  const tdExp = td('tabular-nums');
  if (key.end_date) {
    const expDate = new Date(key.end_date);
    const expDiv = document.createElement('div');
    expDiv.textContent = expDate.toLocaleDateString();
    const daysLeft = Math.ceil((expDate - now) / 86400000);
    const daysDiv = document.createElement('div');
    daysDiv.className = daysLeft < 0 ? 'text-red-500' : daysLeft < 7 ? 'text-amber-500' : 'text-gray-400';
    daysDiv.textContent = daysLeft < 0 ? 'Expired' : `${daysLeft}d left`;
    tdExp.append(expDiv, daysDiv);
  } else {
    tdExp.textContent = '—';
  }

  // ── Action Buttons ──
  const tdActions = td();
  tdActions.className += ' whitespace-nowrap';

  const actionsWrap = document.createElement('div');
  actionsWrap.className = 'flex items-center gap-1 flex-wrap';

  const btnDefs = [
    {
      label: 'Reset HWID',
      title: 'Reset locked HWID',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99"/>`,
      cls: 'text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/30',
      action: () => resetHwid(key.id, key.key_string),
    },
    {
      label: hwidEnabled ? 'Disable HWID' : 'Enable HWID',
      title: hwidEnabled ? 'Disable HWID lock' : 'Enable HWID lock',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0H3"/>`,
      cls: 'text-violet-600 dark:text-violet-400 hover:bg-violet-50 dark:hover:bg-violet-900/30',
      action: () => toggleHwidLock(key.id, key.key_string, hwidEnabled),
    },
    {
      label: key.is_paused ? 'Resume' : 'Pause',
      title: key.is_paused ? 'Resume this license' : 'Pause this license',
      icon: key.is_paused
        ? `<path stroke-linecap="round" stroke-linejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z"/>`
        : `<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25v13.5m-7.5-13.5v13.5"/>`,
      cls: key.is_paused
        ? 'text-emerald-600 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-900/30'
        : 'text-amber-600 dark:text-amber-400 hover:bg-amber-50 dark:hover:bg-amber-900/30',
      action: () => togglePause(key.id, key.key_string, key.is_paused),
    },
    {
      label: 'Extend',
      title: 'Extend expiry date',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 012.25-2.25h13.5A2.25 2.25 0 0121 7.5v11.25m-18 0A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75m-18 0v-7.5A2.25 2.25 0 015.25 9h13.5A2.25 2.25 0 0121 11.25v7.5m-9-6h.008v.008H12v-.008zM12 15h.008v.008H12V15zm0 2.25h.008v.008H12v-.008zM9.75 15h.008v.008H9.75V15zm0 2.25h.008v.008H9.75v-.008zM7.5 15h.008v.008H7.5V15zm0 2.25h.008v.008H7.5v-.008zm6.75-4.5h.008v.008h-.008v-.008zm0 2.25h.008v.008h-.008V15zm0 2.25h.008v.008h-.008v-.008zm2.25-4.5h.008v.008H16.5v-.008zm0 2.25h.008v.008H16.5V15z"/>`,
      cls: 'text-sky-600 dark:text-sky-400 hover:bg-sky-50 dark:hover:bg-sky-900/30',
      action: () => openExtendModal(key.id, key.key_string),
    },
    {
      label: 'Forensic',
      title: 'Open forensic view',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"/>`,
      cls: 'text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700',
      action: () => openForensicModal(key.id, key.key_string),
    },
    {
      label: 'Max Dev.',
      title: 'Update max devices',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0H3"/>`,
      cls: 'text-purple-600 dark:text-purple-400 hover:bg-purple-50 dark:hover:bg-purple-900/30',
      action: () => updateMaxDevices(key.id, key.key_string, key.max_devices ?? 1),
    },
    {
      label: 'Delete',
      title: 'Permanently delete this key',
      icon: `<path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/>`,
      cls: 'text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/30',
      action: () => deleteKey(key.id, key.key_string),
    },
  ];

  btnDefs.forEach(({ label, title, icon, cls, action }) => {
    const btn = document.createElement('button');
    btn.title = title;
    btn.className = `inline-flex items-center gap-1 px-2 py-1 rounded-md text-[10px] font-medium transition ${cls}`;
    btn.innerHTML = `<svg class="w-3 h-3" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">${icon}</svg>${label}`;
    btn.addEventListener('click', action);
    actionsWrap.appendChild(btn);
  });

  tdActions.appendChild(actionsWrap);

  tr.append(tdKey, tdApp, tdClass, tdStatus, tdHwid, tdDevices, tdIp, tdExp, tdActions);
  return tr;
}

// ────────────────────────────────────────────────────────────────────────────────
// Filters
// ────────────────────────────────────────────────────────────────────────────────

function setupFilters() {
  document.getElementById('filterStatus').addEventListener('change', (e) => {
    _filterStatus = e.target.value;
    _updateClearBtn();
    applyFiltersAndSearch();
  });
  document.getElementById('filterApp').addEventListener('change', (e) => {
    _filterApp = e.target.value;
    _updateClearBtn();
    applyFiltersAndSearch();
  });
  document.getElementById('filterClass').addEventListener('change', (e) => {
    _filterClass = e.target.value;
    _updateClearBtn();
    applyFiltersAndSearch();
  });
}

function clearFilters() {
  _filterStatus = '';
  _filterApp = '';
  _filterClass = '';
  document.getElementById('filterStatus').value = '';
  document.getElementById('filterApp').value    = '';
  document.getElementById('filterClass').value  = '';
  document.getElementById('searchInput').value  = '';
  _updateClearBtn();
  applyFiltersAndSearch();
}

function _updateClearBtn() {
  const active = _filterStatus || _filterApp || _filterClass || document.getElementById('searchInput').value.trim();
  document.getElementById('clearFiltersBtn').classList.toggle('hidden', !active);
}

function applyFiltersAndSearch() {
  const q   = document.getElementById('searchInput').value.trim().toLowerCase();
  const now = new Date();

  const filtered = allKeys.filter(k => {
    const expired = k.end_date && new Date(k.end_date) < now;
    const rowStatus = k.is_paused ? 'paused' : (expired ? 'expired' : 'active');
    const isOnlineNow = k.last_login_at && (now - new Date(k.last_login_at)) < 300_000;

    // Status filter
    if (_filterStatus) {
      if (_filterStatus === 'suspicious' && !k.is_suspicious)    return false;
      if (_filterStatus === 'online'     && !isOnlineNow)         return false;
      if (_filterStatus === 'active'     && rowStatus !== 'active')  return false;
      if (_filterStatus === 'expired'    && rowStatus !== 'expired') return false;
      if (_filterStatus === 'paused'     && rowStatus !== 'paused')  return false;
    }

    // App filter
    if (_filterApp && (k.app_name ?? '') !== _filterApp) return false;

    // Classification filter
    if (_filterClass && (k.key_class ?? '') !== _filterClass) return false;

    // Text search
    if (q) {
      return (
        (k.key_string       ?? '').toLowerCase().includes(q) ||
        (k.app_name         ?? '').toLowerCase().includes(q) ||
        (k.owner_name       ?? '').toLowerCase().includes(q) ||
        (k.last_ip          ?? '').toLowerCase().includes(q) ||
        (k.last_region      ?? '').toLowerCase().includes(q) ||
        (k.key_class        ?? '').toLowerCase().includes(q) ||
        (k.permission_level ?? '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  renderTable(filtered);
}


// ────────────────────────────────────────────────────────────────────────────────
// Search
// ────────────────────────────────────────────────────────────────────────────────

let searchDebounceTimer = null;

function setupSearch() {
  const input = document.getElementById('searchInput');
  input.addEventListener('input', () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
      _updateClearBtn();
      applyFiltersAndSearch();
    }, 220);
  });
}

// ────────────────────────────────────────────────────────────────────────────────
// Add New Key Form
// ────────────────────────────────────────────────────────────────────────────────

function toggleAddKeyForm() {
  const form    = document.getElementById('addKeyForm');
  const chevron = document.getElementById('addKeyChevron');
  const hidden  = form.classList.toggle('hidden');
  chevron.style.transform = hidden ? '' : 'rotate(180deg)';
  if (!hidden) {
    // Pre-fill today's date
    document.getElementById('newStartDate').value = new Date().toISOString().slice(0, 10);
    document.getElementById('newAppName').focus();
  }
}

// Show/hide custom duration input when "Custom…" is selected — wired up in DOMContentLoaded

async function addKey() {
  const appName       = document.getElementById('newAppName').value.trim();
  const ownerName      = document.getElementById('newOwnerName').value.trim();
  const durationSel    = document.getElementById('newDuration').value;
  const maxDevices     = parseInt(document.getElementById('newMaxDevices').value, 10) || 1;
  const hwidLock       = document.getElementById('newHwidLock').checked;
  const startDate      = document.getElementById('newStartDate').value;
  const keyClass       = document.getElementById('newKeyClass').value;
  const permissionLevel= document.getElementById('newPermissionLevel').value;
  const adminNote      = document.getElementById('newAdminNote').value.trim() || null;

  let days;
  if (durationSel === 'custom') {
    days = parseInt(document.getElementById('newDurationCustom').value, 10);
    if (!Number.isInteger(days) || days < 1) {
      showToast('Please enter a valid custom duration.', 'warning');
      return;
    }
  } else {
    days = parseInt(durationSel, 10);
  }

  if (!appName) {
    showToast('App Name is required.', 'warning');
    document.getElementById('newAppName').focus();
    return;
  }

  const payload = {
    app_name:          appName,
    owner_name:        ownerName || null,
    duration_days:     days,
    max_devices:       maxDevices,
    hwid_lock_enabled: hwidLock,
    start_date:        startDate || null,
    key_class:         keyClass,
    permission_level:  permissionLevel,
    admin_note:        adminNote,
  };

  try {
    await apiFetch('/keys', { method: 'POST', body: JSON.stringify(payload) });
    showToast('License key created successfully.', 'success');
    // Reset form fields
    document.getElementById('newAppName').value          = '';
    document.getElementById('newOwnerName').value         = '';
    document.getElementById('newDuration').value          = '365';
    document.getElementById('newMaxDevices').value        = '1';
    document.getElementById('newHwidLock').checked        = false;
    document.getElementById('newKeyClass').value          = 'Subscription';
    document.getElementById('newPermissionLevel').value   = 'User';
    document.getElementById('newAdminNote').value         = '';
    document.getElementById('newDurationCustomWrap').classList.add('hidden');
    toggleAddKeyForm();
    refreshAll();
  } catch (err) {
    showToast(`Failed to create key: ${err.message}`, 'error');
  }
}


// ────────────────────────────────────────────────────────────────────────────────
// Action Handlers
// ─────────────────────────────────────────────────────────────────────────────

async function resetHwid(id, keyString) {
  if (!confirm(`Reset locked HWID for key:\n${keyString}\n\nThis will allow the next device to bind.`)) return;
  try {
    await apiFetch(`/keys/${id}/reset-hwid`, { method: 'POST' });
    showToast('HWID reset successfully.', 'success');
    refreshAll();
  } catch (err) {
    showToast(`Reset failed: ${err.message}`, 'error');
  }
}

async function toggleHwidLock(id, keyString, currentlyEnabled) {
  const action = currentlyEnabled ? 'disable' : 'enable';
  if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} HWID lock for key:\n${keyString}`)) return;
  try {
    await apiFetch(`/keys/${id}/toggle-hwid-lock`, { method: 'POST' });
    showToast(`HWID lock ${action}d.`, 'success');
    refreshAll();
  } catch (err) {
    showToast(`Failed to ${action} HWID lock: ${err.message}`, 'error');
  }
}

async function togglePause(id, keyString, currentlyPaused) {
  const action = currentlyPaused ? 'resume' : 'pause';
  if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} key:\n${keyString}`)) return;
  try {
    await apiFetch(`/keys/${id}/toggle-pause`, { method: 'POST' });
    showToast(`Key ${action}d.`, currentlyPaused ? 'success' : 'warning');
    refreshAll();
  } catch (err) {
    showToast(`Failed to ${action} key: ${err.message}`, 'error');
  }
}

async function deleteKey(id, keyString) {
  if (!confirm(`Permanently DELETE key:\n${keyString}\n\nThis action cannot be undone.`)) return;
  try {
    await apiFetch(`/keys/${id}`, { method: 'DELETE' });
    showToast('Key deleted.', 'success');
    refreshAll();
  } catch (err) {
    showToast(`Delete failed: ${err.message}`, 'error');
  }
}

async function updateMaxDevices(id, keyString, current) {
  const input = prompt(`Update max devices for key:\n${keyString}\n\nEnter new value (current: ${current}):`, String(current));
  if (input === null) return;  // cancelled
  const val = parseInt(input, 10);
  if (!Number.isInteger(val) || val < 1 || val > 999) {
    showToast('Please enter a valid number between 1 and 999.', 'warning');
    return;
  }
  try {
    await apiFetch(`/keys/${id}/update-max-devices`, {
      method: 'POST',
      body: JSON.stringify({ max_devices: val }),
    });
    showToast(`Max devices updated to ${val}.`, 'success');
    refreshAll();
  } catch (err) {
    showToast(`Update failed: ${err.message}`, 'error');
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Extend Time Modal
// ─────────────────────────────────────────────────────────────────────────────

let _extendKeyId = null;

function openExtendModal(id, keyString) {
  _extendKeyId = id;
  document.getElementById('extendKeyLabel').textContent = keyString;
  document.getElementById('extendDays').value    = '0';
  document.getElementById('extendHours').value   = '0';
  document.getElementById('extendMinutes').value = '0';
  document.getElementById('extendOverlay').classList.remove('hidden');
  document.getElementById('extendDays').focus();
}

function closeExtendModal() {
  _extendKeyId = null;
  document.getElementById('extendOverlay').classList.add('hidden');
}

async function confirmExtend() {
  if (!_extendKeyId) return;
  const days    = Math.max(0, parseInt(document.getElementById('extendDays').value,    10) || 0);
  const hours   = Math.max(0, parseInt(document.getElementById('extendHours').value,   10) || 0);
  const minutes = Math.max(0, parseInt(document.getElementById('extendMinutes').value, 10) || 0);

  if (days + hours + minutes === 0) {
    showToast('Please enter at least 1 day, hour, or minute.', 'warning');
    return;
  }

  const parts = [];
  if (days)    parts.push(`${days} day${days !== 1 ? 's' : ''}`);
  if (hours)   parts.push(`${hours} hour${hours !== 1 ? 's' : ''}`);
  if (minutes) parts.push(`${minutes} minute${minutes !== 1 ? 's' : ''}`);

  try {
    await apiFetch(`/keys/${_extendKeyId}/extend`, {
      method: 'POST',
      body: JSON.stringify({ days, hours, minutes }),
    });
    showToast(`License extended by ${parts.join(', ')}.`, 'success');
    closeExtendModal();
    refreshAll();
  } catch (err) {
    showToast(`Extend failed: ${err.message}`, 'error');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Forensic View Modal
// ─────────────────────────────────────────────────────────────────────────────

async function openForensicModal(id, keyString) {
  _forensicKeyId  = id;
  _forensicData   = null;
  _setForensicEditMode(false);  // Always open in read-only mode
  const overlay = document.getElementById('forensicOverlay');
  document.getElementById('forensicKeyLabel').textContent = keyString;

  // Show overlay with loading state
  setForensicLoading(true);
  overlay.classList.remove('hidden');

  try {
    const data = await apiFetch(`/keys/${id}/forensic`);
    _forensicData = data;
    renderForensicModal(data);
  } catch (err) {
    showToast(`Could not load forensic data: ${err.message}`, 'error');
    overlay.classList.add('hidden');
  } finally {
    setForensicLoading(false);
  }
}

function setForensicLoading(loading) {
  const details  = document.getElementById('forensicDetails');
  const device   = document.getElementById('forensicDevice');
  const activity = document.getElementById('forensicActivity');
  const history  = document.getElementById('forensicLoginHistory');
  const loadingHtml = `<span class="col-span-3 text-gray-400 py-2">Loading…</span>`;
  if (loading) {
    details.innerHTML = loadingHtml;
    device.innerHTML  = loadingHtml;
    activity.innerHTML= loadingHtml;
    history.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-gray-400">Loading…</td></tr>`;
  }
}

/**
 * Renders all sections of the forensic modal from an API response.
 * @param {object} data - Forensic data object from /api/v1/admin/keys/{id}/forensic
 */
function renderForensicModal(data) {
  const key = data.key ?? data;
  const isOnline = !!data.currently_online;

  // ── Key Details section ──
  renderDl('forensicDetails', [
    { label: 'App Name',         value: key.app_name },
    { label: 'Owner',            value: key.owner_name },
    { label: 'Key Class',        value: key.key_class },
    { label: 'Permission Level', value: key.permission_level },
    { label: 'Status',           value: key.is_paused ? 'Paused' : 'Active' },
    { label: 'Start Date',       value: formatDatetime(key.start_date) },
    { label: 'End Date',         value: formatDatetime(key.end_date) },
    { label: 'Suspicious',       value: key.is_suspicious ? '⚠ Yes' : 'No', danger: key.is_suspicious },
  ]);

  // Populate admin note textarea
  const noteEl = document.getElementById('forensicAdminNote');
  if (noteEl) noteEl.value = key.admin_note ?? '';

  // ── Device & HWID section ──
  renderDl('forensicDevice', [
    { label: 'HWID Lock',       value: key.hwid_lock_enabled ? 'Enabled' : 'Disabled' },
    { label: 'Locked HWID',     value: key.locked_hwid, mono: true },
    { label: 'Max Devices',     value: key.max_devices },
    { label: 'Current Devices', value: key.current_devices },
    { label: 'HWID Reset Count',value: key.hwid_reset_count },
    { label: 'Last Region',     value: key.last_region },
  ]);

  // ── Activity Metrics section ──
  renderDl('forensicActivity', [
    { label: 'First Login',       value: formatDatetime(key.first_login_at) },
    { label: 'Last Login',        value: formatDatetime(key.last_login_at) },
    { label: 'Last IP',           value: key.last_ip, mono: true },
    { label: 'First Region',      value: key.first_region },
    { label: 'Last Region',       value: key.last_region },
    { label: 'Logins (24h)',      value: key.logins_last_24h },
    { label: 'Total Usage',       value: formatUsage(key.total_usage_seconds) },
    { label: 'Currently Online',  value: isOnline ? '● Online' : 'Offline', success: isOnline, danger: false },
  ]);

  // ── Login History table ──
  const histBody = document.getElementById('forensicLoginHistory');
  const logins = data.login_history ?? [];

  if (logins.length === 0) {
    histBody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-gray-400 dark:text-gray-500">No login records found.</td></tr>`;
    return;
  }

  const frag = document.createDocumentFragment();
  logins.forEach((entry, idx) => {
    const tr = document.createElement('tr');
    tr.className = 'text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800/50';

    const cells = [
      String(idx + 1),
      formatDatetime(entry.logged_at),
      entry.ip_address  ?? '—',
      entry.region      ?? '—',
      entry.hwid        ?? '—',
    ];

    cells.forEach((val, i) => {
      const td = document.createElement('td');
      td.className = `px-4 py-2 ${i === 2 || i === 4 ? 'font-mono' : ''}`;
      td.textContent = val;
      tr.appendChild(td);
    });

    frag.appendChild(tr);
  });
  histBody.replaceChildren(frag);
}

/**
 * Populates a <dl> element with label/value pairs.
 * @param {string} elId
 * @param {Array<{label:string, value:*, mono?:boolean, danger?:boolean}>} items
 */
function renderDl(elId, items) {
  const dl = document.getElementById(elId);
  const frag = document.createDocumentFragment();

  items.forEach(({ label, value, mono = false, danger = false, success = false }) => {
    const div = document.createElement('div');
    div.className = 'bg-gray-50 dark:bg-gray-800/60 rounded-lg px-3 py-2';

    const dt = document.createElement('dt');
    dt.className = 'text-[10px] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-0.5';
    dt.textContent = label;

    const dd = document.createElement('dd');
    dd.className = `text-xs font-medium break-all ${mono ? 'font-mono' : ''} ${
      danger  ? 'text-red-600 dark:text-red-400'     :
      success ? 'text-emerald-600 dark:text-emerald-400' :
      'text-gray-900 dark:text-gray-100'
    }`;
    dd.textContent = value !== null && value !== undefined ? String(value) : '—';

    div.append(dt, dd);
    frag.appendChild(div);
  });

  dl.replaceChildren(frag);
}

function closeForensicModal() {
  _setForensicEditMode(false);
  document.getElementById('forensicOverlay').classList.add('hidden');
  _forensicKeyId = null;
  _forensicData  = null;
}

// ── Forensic Edit Mode helpers ───────────────────────────────────────────────

function _setForensicEditMode(active) {
  _forensicEditMode = active;
  document.getElementById('forensicDetails').classList.toggle('hidden', active);
  document.getElementById('forensicEditForm').classList.toggle('hidden', !active);
  document.getElementById('forensicEditBtn').classList.toggle('hidden', active);
  document.getElementById('forensicSaveNoteBtn').classList.toggle('hidden', active);
  document.getElementById('forensicCancelEditBtn').classList.toggle('hidden', !active);
  document.getElementById('forensicSaveAllBtn').classList.toggle('hidden', !active);
}

function enterForensicEditMode() {
  if (!_forensicData) return;
  const key = _forensicData.key ?? _forensicData;
  document.getElementById('editAppName').value         = key.app_name ?? '';
  document.getElementById('editOwnerName').value       = key.owner_name ?? '';
  document.getElementById('editKeyClass').value        = key.key_class ?? 'Subscription';
  document.getElementById('editPermissionLevel').value = key.permission_level ?? 'User';
  // Slice to "YYYY-MM-DDTHH:MM" — the server stores and receives UTC datetimes
  document.getElementById('editEndDate').value = key.end_date ? key.end_date.slice(0, 16) : '';
  _setForensicEditMode(true);
}

function cancelForensicEdit() {
  _setForensicEditMode(false);
  // Re-render read-only view to revert any note changes the admin typed but didn't save
  if (_forensicData) renderForensicModal(_forensicData);
}

async function saveForensicEdit() {
  if (!_forensicKeyId) return;
  const appName         = document.getElementById('editAppName').value.trim();
  const ownerName       = document.getElementById('editOwnerName').value.trim();
  const keyClass        = document.getElementById('editKeyClass').value;
  const permissionLevel = document.getElementById('editPermissionLevel').value;
  const endDateVal      = document.getElementById('editEndDate').value; // "YYYY-MM-DDTHH:MM"
  const adminNote       = document.getElementById('forensicAdminNote').value.trim() || null;

  if (!appName) {
    showToast('App Name cannot be empty.', 'warning');
    document.getElementById('editAppName').focus();
    return;
  }
  if (!endDateVal) {
    showToast('End Date is required.', 'warning');
    return;
  }

  const payload = {
    app_name:         appName,
    owner_name:       ownerName || null,
    key_class:        keyClass,
    permission_level: permissionLevel,
    end_date:         endDateVal + ':00',  // "YYYY-MM-DDTHH:MM:SS" — stored as UTC
    admin_note:       adminNote,
  };

  const btn = document.getElementById('forensicSaveAllBtn');
  btn.disabled = true;
  btn.textContent = 'Saving…';

  try {
    const updated = await apiFetch(`/keys/${_forensicKeyId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
    _forensicData = { ..._forensicData, key: updated };
    _setForensicEditMode(false);
    renderForensicModal(_forensicData);
    showToast('Changes saved successfully.', 'success');
    refreshAll();
  } catch (err) {
    showToast(`Save failed: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save All Changes';
  }
}

async function saveAdminNote() {
  if (!_forensicKeyId) return;
  const note = document.getElementById('forensicAdminNote').value.trim() || null;
  try {
    await apiFetch(`/keys/${_forensicKeyId}/update-note`, {
      method: 'POST',
      body: JSON.stringify({ admin_note: note }),
    });
    showToast('Admin note saved.', 'success');
  } catch (err) {
    showToast(`Save failed: ${err.message}`, 'error');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility Formatters
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Formats an ISO datetime string to a human-readable UTC string.
 * @param {string|null} iso
 * @returns {string}
 */
function formatDatetime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/**
 * Converts total seconds into a readable duration string.
 * @param {number|null} seconds
 * @returns {string}
 */
function formatUsage(seconds) {
  if (seconds == null) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Refresh (stats + table)
// ─────────────────────────────────────────────────────────────────────────────

function refreshAll() {
  const icon = document.getElementById('refreshIcon');
  icon.classList.add('animate-spin');
  Promise.all([loadStats(), loadKeys()]).finally(() => {
    setTimeout(() => icon.classList.remove('animate-spin'), 600);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard shortcuts
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('keydown', (e) => {
  // Escape closes any open modal
  if (e.key === 'Escape') {
    closeForensicModal();
    closeExtendModal();
  }
  // Ctrl/Cmd + K focuses search
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    document.getElementById('searchInput').focus();
  }
});

// Close modals on backdrop click
document.getElementById('forensicOverlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeForensicModal();
});
document.getElementById('extendOverlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeExtendModal();
});

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  // Guard: redirect to login if no token is present
  if (!localStorage.getItem(TOKEN_KEY)) {
    window.location.href = 'index.html';
    return;
  }

  initDarkMode();
  setupSearch();
  refreshAll();

  document.getElementById('darkToggle').addEventListener('click', toggleDarkMode);
  document.getElementById('refreshBtn').addEventListener('click', refreshAll);
  document.getElementById('extendConfirmBtn').addEventListener('click', confirmExtend);
  ['extendDays', 'extendHours', 'extendMinutes'].forEach(id => {
    document.getElementById(id).addEventListener('keydown', (e) => {
      if (e.key === 'Enter') confirmExtend();
    });
  });
  setupFilters();
  document.getElementById('newDuration').addEventListener('change', (e) => {
    const wrap = document.getElementById('newDurationCustomWrap');
    wrap.classList.toggle('hidden', e.target.value !== 'custom');
  });
});
