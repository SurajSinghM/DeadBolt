/* ═══════════════════════════════════════════════════
   DeadBolt — Core Extension Logic
   AES-256-GCM encrypted vault with PBKDF2 key derivation
   ═══════════════════════════════════════════════════ */

(() => {
  'use strict';

  // ── Constants ──
  const STORAGE_KEYS = {
    VAULT: 'deadbolt_vault',
    SALT: 'deadbolt_salt',
    IV: 'deadbolt_iv',
    VERIFY: 'deadbolt_verify',
    SETTINGS: 'deadbolt_settings'
  };
  const VERIFY_PHRASE = 'DEADBOLT_VAULT_OK';
  const PBKDF2_ITERATIONS = 100000;

  // ── State ──
  let state = {
    entries: [],
    cryptoKey: null,
    salt: null,
    editingId: null,
    generatorCallback: null,
    settings: { autoLockMinutes: 5 }
  };

  // ══════════════════════════════════
  //  CRYPTO UTILITIES (Web Crypto API)
  // ══════════════════════════════════

  function getRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true, // Allow extractable to save to session storage
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(data, key) {
    const encoder = new TextEncoder();
    const iv = getRandomBytes(12);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(JSON.stringify(data))
    );
    return { ciphertext: bufferToBase64(encrypted), iv: bufferToBase64(iv) };
  }

  async function decrypt(ciphertext, iv, key) {
    const decoder = new TextDecoder();
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuffer(iv) },
      key,
      base64ToBuffer(ciphertext)
    );
    return JSON.parse(decoder.decode(decrypted));
  }

  // ══════════════════════════════════
  //  STORAGE HELPERS
  // ══════════════════════════════════

  function storageGet(keys) {
    return new Promise(resolve => chrome.storage.local.get(keys, resolve));
  }

  function storageSet(data) {
    return new Promise(resolve => chrome.storage.local.set(data, resolve));
  }

  function storageRemove(keys) {
    return new Promise(resolve => chrome.storage.local.remove(keys, resolve));
  }

  async function sessionSetKey(key, salt) {
    const rawKey = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.local.set({
      deadbolt_session_key: bufferToBase64(rawKey),
      deadbolt_session_salt: bufferToBase64(salt)
    });
  }

  function sessionClear() {
    chrome.storage.local.remove(['deadbolt_session_key', 'deadbolt_session_salt']);
  }

  // ══════════════════════════════════
  //  VAULT OPERATIONS
  // ══════════════════════════════════

  async function vaultExists() {
    const data = await storageGet([STORAGE_KEYS.VAULT, STORAGE_KEYS.SALT]);
    return !!(data[STORAGE_KEYS.VAULT] && data[STORAGE_KEYS.SALT]);
  }

  async function createVault(masterPassword) {
    const salt = getRandomBytes(32);
    state.salt = salt;
    state.cryptoKey = await deriveKey(masterPassword, salt);
    state.entries = [];

    const verifyData = await encrypt(VERIFY_PHRASE, state.cryptoKey);
    const vaultData = await encrypt(state.entries, state.cryptoKey);

    await storageSet({
      [STORAGE_KEYS.SALT]: bufferToBase64(salt),
      [STORAGE_KEYS.VAULT]: vaultData.ciphertext,
      [STORAGE_KEYS.IV]: vaultData.iv,
      [STORAGE_KEYS.VERIFY]: JSON.stringify(verifyData),
      [STORAGE_KEYS.SETTINGS]: JSON.stringify(state.settings)
    });

    await sessionSetKey(state.cryptoKey, state.salt);
    notifyBackground('vault-unlocked');
  }

  async function unlockVault(masterPassword) {
    const data = await storageGet([
      STORAGE_KEYS.SALT, STORAGE_KEYS.VAULT, STORAGE_KEYS.IV, STORAGE_KEYS.VERIFY, STORAGE_KEYS.SETTINGS
    ]);

    const salt = base64ToBuffer(data[STORAGE_KEYS.SALT]);
    const key = await deriveKey(masterPassword, salt);

    // Verify password by decrypting the verification phrase
    const verifyData = JSON.parse(data[STORAGE_KEYS.VERIFY]);
    try {
      const phrase = await decrypt(verifyData.ciphertext, verifyData.iv, key);
      if (phrase !== VERIFY_PHRASE) throw new Error('Verification failed');
    } catch {
      throw new Error('Incorrect master password');
    }

    state.cryptoKey = key;
    state.salt = new Uint8Array(salt);

    // Decrypt vault entries
    if (data[STORAGE_KEYS.VAULT] && data[STORAGE_KEYS.IV]) {
      state.entries = await decrypt(data[STORAGE_KEYS.VAULT], data[STORAGE_KEYS.IV], key);
    } else {
      state.entries = [];
    }

    // Load settings
    if (data[STORAGE_KEYS.SETTINGS]) {
      try { state.settings = JSON.parse(data[STORAGE_KEYS.SETTINGS]); } catch {}
    }

    await sessionSetKey(state.cryptoKey, state.salt);
    notifyBackground('vault-unlocked');
  }

  async function saveVault() {
    if (!state.cryptoKey) return;
    const vaultData = await encrypt(state.entries, state.cryptoKey);
    await storageSet({
      [STORAGE_KEYS.VAULT]: vaultData.ciphertext,
      [STORAGE_KEYS.IV]: vaultData.iv
    });
  }

  async function saveSettings() {
    await storageSet({ [STORAGE_KEYS.SETTINGS]: JSON.stringify(state.settings) });
  }

  function lockVault() {
    state.cryptoKey = null;
    state.entries = [];
    state.editingId = null;
    sessionClear();
    notifyBackground('vault-locked');
    showScreen('screen-login');
  }

  async function destroyVault() {
    await storageRemove(Object.values(STORAGE_KEYS));
    state.cryptoKey = null;
    state.entries = [];
    state.salt = null;
    state.editingId = null;
    sessionClear();
    notifyBackground('vault-locked');
    showScreen('screen-setup');
  }

  async function changeMasterPassword(currentPass, newPass) {
    // Re-derive current key and verify
    const data = await storageGet([STORAGE_KEYS.SALT, STORAGE_KEYS.VERIFY]);
    const salt = base64ToBuffer(data[STORAGE_KEYS.SALT]);
    const oldKey = await deriveKey(currentPass, salt);

    const verifyData = JSON.parse(data[STORAGE_KEYS.VERIFY]);
    try {
      const phrase = await decrypt(verifyData.ciphertext, verifyData.iv, oldKey);
      if (phrase !== VERIFY_PHRASE) throw new Error();
    } catch {
      throw new Error('Current password is incorrect');
    }

    // Create new salt + key, re-encrypt everything
    const newSalt = getRandomBytes(32);
    const newKey = await deriveKey(newPass, newSalt);

    state.cryptoKey = newKey;
    state.salt = newSalt;

    const newVerify = await encrypt(VERIFY_PHRASE, newKey);
    const newVault = await encrypt(state.entries, newKey);

    await storageSet({
      [STORAGE_KEYS.SALT]: bufferToBase64(newSalt),
      [STORAGE_KEYS.VAULT]: newVault.ciphertext,
      [STORAGE_KEYS.IV]: newVault.iv,
      [STORAGE_KEYS.VERIFY]: JSON.stringify(newVerify)
    });
  }

  // ══════════════════════════════════
  //  PASSWORD GENERATOR
  // ══════════════════════════════════

  const CHARSETS = {
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    digits:  '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  function generatePassword(length, options) {
    let charset = '';
    if (options.upper)   charset += CHARSETS.upper;
    if (options.lower)   charset += CHARSETS.lower;
    if (options.digits)  charset += CHARSETS.digits;
    if (options.symbols) charset += CHARSETS.symbols;
    if (!charset) charset = CHARSETS.lower;

    const array = getRandomBytes(length);
    let password = '';
    for (let i = 0; i < length; i++) {
      password += charset[array[i] % charset.length];
    }
    return password;
  }

  function calcPasswordStrength(password) {
    if (!password) return { score: 0, label: '', level: '' };
    let score = 0;
    if (password.length >= 8)  score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    if (password.length >= 20) score++;

    if (score <= 2) return { score, label: 'Weak', level: 'weak', pct: 25 };
    if (score <= 3) return { score, label: 'Fair', level: 'fair', pct: 50 };
    if (score <= 5) return { score, label: 'Good', level: 'good', pct: 75 };
    return { score, label: 'Strong', level: 'strong', pct: 100 };
  }

  function updateStrengthUI(fillEl, labelEl, password) {
    const s = calcPasswordStrength(password);
    fillEl.style.width = s.pct + '%';
    fillEl.style.background = `var(--strength-${s.level})`;
    labelEl.textContent = s.label;
    labelEl.style.color = `var(--strength-${s.level})`;
  }

  // ══════════════════════════════════
  //  BACKGROUND COMMUNICATION
  // ══════════════════════════════════

  function notifyBackground(action, data = {}) {
    try {
      chrome.runtime.sendMessage({ action, ...data });
    } catch { /* popup closing */ }
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === 'force-lock') {
      lockVault();
    }
  });

  // ══════════════════════════════════
  //  UI UTILITIES
  // ══════════════════════════════════

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  function showScreen(id) {
    $$('.screen').forEach(s => s.style.display = 'none');
    const screen = $(`#${id}`);
    if (screen) {
      screen.style.display = 'flex';
      screen.style.animation = 'none';
      void screen.offsetHeight;
      screen.style.animation = '';
    }

    // Toggle bottom nav visibility
    const nav = $('#bottom-nav');
    if (['screen-vault', 'screen-generator', 'screen-breach', 'screen-settings'].includes(id)) {
      nav.style.display = 'flex';
      $$('.nav-item').forEach(btn => btn.classList.remove('active'));
      if (id === 'screen-vault') $('#btn-vault').classList.add('active');
      if (id === 'screen-generator') $('#btn-generator').classList.add('active');
      if (id === 'screen-breach') $('#btn-breach').classList.add('active');
      if (id === 'screen-settings') $('#btn-settings').classList.add('active');
    } else {
      nav.style.display = 'none';
    }
  }

  function showToast(message, type = 'success') {
    const toast = $('#toast');
    toast.textContent = message;
    toast.className = 'toast show ' + type;
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.className = 'toast'; }, 2500);
  }

  function confirm(title, message) {
    return new Promise(resolve => {
      const overlay = document.createElement('div');
      overlay.className = 'confirm-overlay';
      overlay.innerHTML = `
        <div class="confirm-dialog">
          <h3>${title}</h3>
          <p>${message}</p>
          <div class="confirm-actions">
            <button class="btn-secondary" id="confirm-cancel">Cancel</button>
            <button class="btn-danger-full" id="confirm-ok">Confirm</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);

      overlay.querySelector('#confirm-cancel').onclick = () => { overlay.remove(); resolve(false); };
      overlay.querySelector('#confirm-ok').onclick = () => { overlay.remove(); resolve(true); };
    });
  }

  function getFaviconUrl(url) {
    try {
      const u = new URL(url.startsWith('http') ? url : 'https://' + url);
      return `https://www.google.com/s2/favicons?domain=${u.hostname}&sz=64`;
    } catch {
      return null;
    }
  }

  function getInitial(title) {
    return (title || '?')[0].toUpperCase();
  }

  function generateId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
  }

  function domainFromUrl(url) {
    try {
      return new URL(url.startsWith('http') ? url : 'https://' + url).hostname.replace(/^www\./, '');
    } catch {
      return '';
    }
  }

  // ══════════════════════════════════
  //  RENDER ENTRIES LIST
  // ══════════════════════════════════

  function renderEntries(filter = '') {
    const list = $('#entries-list');
    const empty = $('#empty-state');
    const search = filter.toLowerCase().trim();

    let filtered = state.entries;
    if (search) {
      filtered = state.entries.filter(e =>
        (e.title || '').toLowerCase().includes(search) ||
        (e.username || '').toLowerCase().includes(search) ||
        (e.url || '').toLowerCase().includes(search) ||
        (e.notes || '').toLowerCase().includes(search)
      );
    }

    if (filtered.length === 0) {
      list.style.display = 'none';
      empty.style.display = 'flex';
      if (search) {
        empty.querySelector('p').textContent = 'No results found';
        empty.querySelector('span').textContent = `No entries match "${filter}"`;
      } else {
        empty.querySelector('p').textContent = 'Your vault is empty';
        empty.querySelector('span').textContent = 'Add your first password below';
      }
      return;
    }

    list.style.display = 'flex';
    empty.style.display = 'none';

    list.innerHTML = filtered.map((entry, i) => {
      const favicon = getFaviconUrl(entry.url);
      const faviconContent = favicon
        ? `<img src="${favicon}" alt="" onerror="this.parentNode.textContent='${getInitial(entry.title)}'" style="width: 20px; height: 20px; border-radius: 4px;">`
        : getInitial(entry.title);

      return `
        <div class="entry-card" data-id="${entry.id}" style="animation-delay: ${i * 30}ms">
          <div class="entry-icon">${faviconContent}</div>
          <div class="entry-info">
            <div class="entry-title">${escapeHtml(entry.title || 'Untitled')}</div>
            <div class="entry-user">${escapeHtml(entry.username || '—')}</div>
          </div>
          <div class="entry-actions">
            <button class="btn-action" data-action="copy-user" data-id="${entry.id}" title="Copy username">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </button>
            <button class="btn-action" data-action="copy-pass" data-id="${entry.id}" title="Copy password">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </button>
            <button class="btn-action" data-action="autofill" data-id="${entry.id}" title="Auto-fill">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4M10 17l5-5-5-5M15 12H3"/></svg>
            </button>
          </div>
        </div>`;
    }).join('');
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ══════════════════════════════════
  //  AUTO-FILL
  // ══════════════════════════════════

  async function autofillEntry(entryId) {
    const entry = state.entries.find(e => e.id === entryId);
    if (!entry) return;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.id) return;

      await chrome.tabs.sendMessage(tab.id, {
        action: 'autofill',
        username: entry.username || '',
        password: entry.password || ''
      });
      showToast('Credentials filled!');
      setTimeout(() => window.close(), 800);
    } catch {
      showToast('Cannot auto-fill on this page', 'error');
    }
  }

  // ══════════════════════════════════
  //  BREACH CHECK (Have I Been Pwned)
  // ══════════════════════════════════

  async function sha1Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async function checkHIBP(password) {
    const hash = await sha1Hash(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    try {
      const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' }
      });
      if (!response.ok) return 0;

      const text = await response.text();
      const lines = text.split('\n');
      for (const line of lines) {
        const [hashSuffix, count] = line.trim().split(':');
        if (hashSuffix === suffix) {
          return parseInt(count, 10);
        }
      }
      return 0;
    } catch {
      return -1; // network error
    }
  }

  let breachResults = [];
  let isScanning = false;

  async function checkBreaches() {
    if (isScanning) return;
    if (state.entries.length === 0) {
      showToast('No entries in vault to check', 'error');
      return;
    }

    isScanning = true;
    breachResults = [];

    const shield = $('#breach-shield');
    const scanBtn = $('#btn-scan-breach');
    const progress = $('#breach-progress');
    const progressFill = $('#breach-progress-fill');
    const progressText = $('#breach-progress-text');
    const resultsEl = $('#breach-results');
    const emptyEl = $('#breach-empty');

    // Reset UI
    shield.className = 'breach-shield scanning';
    scanBtn.style.display = 'none';
    progress.style.display = 'block';
    resultsEl.style.display = 'none';
    emptyEl.style.display = 'none';
    progressFill.style.width = '0%';
    $('#breach-title').textContent = 'Scanning...';
    $('#breach-subtitle').textContent = 'Checking your passwords against known breaches';

    const entries = state.entries.filter(e => e.password);
    let checked = 0;
    let errors = 0;

    for (const entry of entries) {
      checked++;
      progressText.textContent = `Checking ${checked} of ${entries.length}...`;
      progressFill.style.width = `${(checked / entries.length) * 100}%`;

      const count = await checkHIBP(entry.password);

      if (count > 0) {
        breachResults.push({
          entryId: entry.id,
          title: entry.title || 'Untitled',
          username: entry.username || '',
          url: entry.url || '',
          breachCount: count
        });
      } else if (count === -1) {
        errors++;
      }

      // Rate limit: 100ms between API calls
      if (checked < entries.length) {
        await new Promise(r => setTimeout(r, 100));
      }
    }

    isScanning = false;
    progress.style.display = 'none';
    scanBtn.style.display = 'flex';
    scanBtn.textContent = 'Scan Again';

    if (breachResults.length > 0) {
      shield.className = 'breach-shield danger';
      $('#breach-title').textContent = `${breachResults.length} compromised`;
      $('#breach-subtitle').textContent = `${breachResults.length} of ${entries.length} passwords found in data breaches`;
      renderBreachResults();
    } else {
      shield.className = 'breach-shield safe';
      $('#breach-title').textContent = 'All clear!';
      const errMsg = errors > 0 ? ` (${errors} could not be checked)` : '';
      $('#breach-subtitle').textContent = `None of your passwords appear in known breaches${errMsg}`;
    }
  }

  function renderBreachResults() {
    const resultsEl = $('#breach-results');
    const listEl = $('#breach-results-list');
    const headingEl = $('#breach-results-heading');

    headingEl.textContent = `Compromised Passwords (${breachResults.length})`;
    resultsEl.style.display = 'block';

    listEl.innerHTML = breachResults.map((result, i) => {
      const favicon = getFaviconUrl(result.url);
      const initial = getInitial(result.title);
      const iconContent = favicon
        ? `<img src="${favicon}" alt="" onerror="this.parentNode.textContent='${initial}'">`
        : initial;

      const countLabel = result.breachCount >= 1000000
        ? `${(result.breachCount / 1000000).toFixed(1)}M`
        : result.breachCount >= 1000
          ? `${(result.breachCount / 1000).toFixed(0)}K`
          : result.breachCount.toString();

      return `
        <div class="breach-result-card" data-breach-id="${result.entryId}" style="animation-delay: ${i * 40}ms">
          <div class="breach-result-icon">${iconContent}</div>
          <div class="breach-result-info">
            <div class="breach-result-title">${escapeHtml(result.title)}</div>
            <div class="breach-result-user">${escapeHtml(result.username || '—')}</div>
          </div>
          <div class="breach-count-badge">${countLabel}×</div>
        </div>`;
    }).join('');
  }

  function resetBreachUI() {
    const shield = $('#breach-shield');
    shield.className = 'breach-shield';
    $('#breach-title').textContent = 'Check your passwords';
    $('#breach-subtitle').textContent = 'Scan your vault against known data breaches';
    $('#btn-scan-breach').textContent = 'Scan Now';
    $('#btn-scan-breach').style.display = 'flex';
    $('#breach-progress').style.display = 'none';
    $('#breach-results').style.display = 'none';
    $('#breach-empty').style.display = 'none';
    breachResults = [];
  }

  // ══════════════════════════════════
  //  EXPORT / IMPORT
  // ══════════════════════════════════

  function exportVault() {
    const data = {
      format: 'deadbolt-v1',
      exported: new Date().toISOString(),
      entries: state.entries.map(e => ({
        title: e.title,
        url: e.url,
        username: e.username,
        password: e.password,
        notes: e.notes,
        created: e.created,
        updated: e.updated
      }))
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `deadbolt-export-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Vault exported!');
  }

  async function importVault(file) {
    try {
      const text = await file.text();
      const data = JSON.parse(text);

      if (!data.entries || !Array.isArray(data.entries)) {
        throw new Error('Invalid file format');
      }

      const count = data.entries.length;
      const ok = await confirm(
        'Import Vault',
        `This will add ${count} entries to your vault. Existing entries will NOT be removed. Continue?`
      );
      if (!ok) return;

      for (const entry of data.entries) {
        state.entries.push({
          id: generateId(),
          title: entry.title || '',
          url: entry.url || '',
          username: entry.username || '',
          password: entry.password || '',
          notes: entry.notes || '',
          created: entry.created || new Date().toISOString(),
          updated: new Date().toISOString()
        });
      }

      await saveVault();
      renderEntries();
      showToast(`Imported ${count} entries!`);
    } catch (err) {
      showToast('Import failed: ' + err.message, 'error');
    }
  }

  // ══════════════════════════════════
  //  EVENT HANDLERS
  // ══════════════════════════════════

  function initEventListeners() {

    // ── Toggle password visibility ──
    $$('.btn-eye').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const targetId = btn.dataset.target;
        const input = $(`#${targetId}`);
        if (!input) return;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        btn.classList.toggle('active', isPassword);
      });
    });

    // ── Setup / Onboarding ──
    $('#btn-open-onboarding').addEventListener('click', () => {
      chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') });
      window.close();
    });

    // ── Login form ──
    $('#form-login').addEventListener('submit', async (e) => {
      e.preventDefault();
      const pass = $('#login-password').value;
      const errorEl = $('#login-error');
      const btn = $('#btn-unlock');

      errorEl.textContent = '';
      btn.disabled = true;
      btn.textContent = 'Unlocking...';

      try {
        await unlockVault(pass);
        showScreen('screen-vault');
        renderEntries();
      } catch {
        errorEl.textContent = 'Incorrect master password';
      } finally {
        btn.disabled = false;
        btn.textContent = 'Unlock';
      }
    });

    // ── Lock button ──
    $('#btn-lock').addEventListener('click', lockVault);

    // ── Search ──
    $('#search-input').addEventListener('input', (e) => {
      const val = e.target.value;
      $('#btn-clear-search').style.display = val ? 'flex' : 'none';
      renderEntries(val);
    });
    $('#btn-clear-search').addEventListener('click', () => {
      $('#search-input').value = '';
      $('#btn-clear-search').style.display = 'none';
      renderEntries();
    });

    // ── Entry list clicks (delegation) ──
    $('#entries-list').addEventListener('click', (e) => {
      const actionBtn = e.target.closest('[data-action]');
      if (actionBtn) {
        e.stopPropagation();
        const action = actionBtn.dataset.action;
        const id = actionBtn.dataset.id;
        const entry = state.entries.find(x => x.id === id);
        if (!entry) return;

        if (action === 'copy-user') {
          navigator.clipboard.writeText(entry.username || '');
          showToast('Username copied!');
        } else if (action === 'copy-pass') {
          navigator.clipboard.writeText(entry.password || '');
          showToast('Password copied!');
        } else if (action === 'autofill') {
          autofillEntry(id);
        }
        return;
      }

      const card = e.target.closest('.entry-card');
      if (card) {
        openEditEntry(card.dataset.id);
      }
    });

    // ── Add entry FAB ──
    $('#btn-add-entry').addEventListener('click', openAddEntry);

    // ── Entry form ──
    $('#btn-back-entry').addEventListener('click', () => {
      state.editingId = null;
      showScreen('screen-vault');
      renderEntries($('#search-input').value);
    });

    $('#form-entry').addEventListener('submit', async (e) => {
      e.preventDefault();
      const entryData = {
        title: $('#entry-title').value.trim(),
        url: $('#entry-url').value.trim(),
        username: $('#entry-username').value.trim(),
        password: $('#entry-password').value,
        notes: $('#entry-notes').value.trim(),
        updated: new Date().toISOString()
      };

      if (state.editingId) {
        const idx = state.entries.findIndex(x => x.id === state.editingId);
        if (idx !== -1) {
          state.entries[idx] = { ...state.entries[idx], ...entryData };
        }
      } else {
        state.entries.push({
          id: generateId(),
          ...entryData,
          created: new Date().toISOString()
        });
      }

      await saveVault();
      state.editingId = null;
      showScreen('screen-vault');
      renderEntries();
      showToast(state.editingId ? 'Entry updated!' : 'Entry saved! 🔑');
    });

    $('#btn-delete-entry').addEventListener('click', async () => {
      if (!state.editingId) return;
      const ok = await confirm('Delete Entry', 'Are you sure you want to delete this entry? This cannot be undone.');
      if (!ok) return;

      state.entries = state.entries.filter(x => x.id !== state.editingId);
      await saveVault();
      state.editingId = null;
      showScreen('screen-vault');
      renderEntries();
      showToast('Entry deleted');
    });

    // ── Generate password inside entry form ──
    $('#btn-gen-entry-pass').addEventListener('click', (e) => {
      e.preventDefault();
      state.generatorCallback = (pass) => {
        $('#entry-password').value = pass;
        $('#entry-password').type = 'text';
        const eyeBtn = document.querySelector('.btn-eye[data-target="entry-password"]');
        if (eyeBtn) eyeBtn.classList.add('active');
      };
      $('#btn-use-gen').style.display = 'flex';
      showScreen('screen-generator');
      generateAndDisplay();
    });

    // ── Generator screen ──
    $('#btn-generator').addEventListener('click', () => {
      state.generatorCallback = null;
      $('#btn-use-gen').style.display = 'none';
      showScreen('screen-generator');
      generateAndDisplay();
    });

    $('#btn-vault').addEventListener('click', () => {
      showScreen('screen-vault');
      renderEntries();
    });

    $('#gen-length').addEventListener('input', (e) => {
      $('#gen-length-val').textContent = e.target.value;
      generateAndDisplay();
    });

    ['gen-upper', 'gen-lower', 'gen-digits', 'gen-symbols'].forEach(id => {
      $(`#${id}`).addEventListener('change', generateAndDisplay);
    });

    $('#btn-refresh-gen').addEventListener('click', generateAndDisplay);

    $('#btn-copy-gen').addEventListener('click', () => {
      const pass = $('#gen-output').textContent;
      navigator.clipboard.writeText(pass);
      showToast('Password copied!');
    });

    $('#btn-use-gen').addEventListener('click', () => {
      const pass = $('#gen-output').textContent;
      if (state.generatorCallback) {
        state.generatorCallback(pass);
        state.generatorCallback = null;
      }
      showScreen('screen-entry');
    });

    // ── Breach check screen ──
    $('#btn-breach').addEventListener('click', () => {
      showScreen('screen-breach');
    });

    $('#btn-scan-breach').addEventListener('click', checkBreaches);

    // ── Breach result clicks (edit entry) ──
    $('#breach-results-list').addEventListener('click', (e) => {
      const card = e.target.closest('[data-breach-id]');
      if (card) {
        openEditEntry(card.dataset.breachId);
      }
    });

    // ── Settings screen ──
    $('#btn-settings').addEventListener('click', () => {
      $('#setting-autolock').value = state.settings.autoLockMinutes;
      $('#setting-autolock-val').textContent = state.settings.autoLockMinutes + ' min';
      $('#setting-current-pass').value = '';
      $('#setting-new-pass').value = '';
      $('#setting-confirm-pass').value = '';
      $('#settings-pass-error').textContent = '';
      showScreen('screen-settings');
    });


    $('#setting-autolock').addEventListener('input', async (e) => {
      const val = parseInt(e.target.value);
      $('#setting-autolock-val').textContent = val + ' min';
      state.settings.autoLockMinutes = val;
      await saveSettings();
      notifyBackground('update-autolock', { minutes: val });
    });

    $('#btn-change-pass').addEventListener('click', async () => {
      const current = $('#setting-current-pass').value;
      const newPass = $('#setting-new-pass').value;
      const conf = $('#setting-confirm-pass').value;
      const errorEl = $('#settings-pass-error');

      if (!current || !newPass) {
        errorEl.textContent = 'All fields are required';
        return;
      }
      if (newPass.length < 4) {
        errorEl.textContent = 'New password must be at least 4 characters';
        return;
      }
      if (newPass !== conf) {
        errorEl.textContent = 'New passwords do not match';
        return;
      }

      try {
        await changeMasterPassword(current, newPass);
        $('#setting-current-pass').value = '';
        $('#setting-new-pass').value = '';
        $('#setting-confirm-pass').value = '';
        errorEl.textContent = '';
        showToast('Master password changed! 🔑');
      } catch (err) {
        errorEl.textContent = err.message;
      }
    });

    // ── Export / Import ──
    $('#btn-export').addEventListener('click', exportVault);
    $('#btn-import').addEventListener('click', () => $('#import-file').click());
    $('#import-file').addEventListener('change', (e) => {
      if (e.target.files[0]) {
        importVault(e.target.files[0]);
        e.target.value = '';
      }
    });

    // ── Destroy vault ──
    $('#btn-destroy-vault').addEventListener('click', async () => {
      const ok = await confirm(
        '⚠️ Destroy Vault',
        'This will permanently delete ALL stored passwords and your master password. This action CANNOT be undone. Are you absolutely sure?'
      );
      if (!ok) return;
      await destroyVault();
      showToast('Vault destroyed', 'error');
    });
  }

  // ── Entry form helpers ──
  function openAddEntry() {
    state.editingId = null;
    $('#entry-form-title').textContent = 'Add Password';
    $('#btn-delete-entry').style.display = 'none';
    $('#entry-title').value = '';
    $('#entry-url').value = '';
    $('#entry-username').value = '';
    $('#entry-password').value = '';
    $('#entry-password').type = 'password';
    $('#entry-notes').value = '';

    // Pre-fill URL from current tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.url && tabs[0].url.startsWith('http')) {
        try {
          const url = new URL(tabs[0].url);
          $('#entry-url').value = url.origin;
          const domain = url.hostname.replace(/^www\./, '');
          const parts = domain.split('.');
          const name = parts.length > 1 ? parts[parts.length - 2] : parts[0];
          $('#entry-title').value = name.charAt(0).toUpperCase() + name.slice(1);
        } catch {}
      }
    });

    showScreen('screen-entry');
  }

  function openEditEntry(id) {
    const entry = state.entries.find(x => x.id === id);
    if (!entry) return;

    state.editingId = id;
    $('#entry-form-title').textContent = 'Edit Password';
    $('#btn-delete-entry').style.display = 'flex';
    $('#entry-title').value = entry.title || '';
    $('#entry-url').value = entry.url || '';
    $('#entry-username').value = entry.username || '';
    $('#entry-password').value = entry.password || '';
    $('#entry-password').type = 'password';
    $('#entry-notes').value = entry.notes || '';

    showScreen('screen-entry');
  }

  function generateAndDisplay() {
    const length = parseInt($('#gen-length').value);
    const options = {
      upper: $('#gen-upper').checked,
      lower: $('#gen-lower').checked,
      digits: $('#gen-digits').checked,
      symbols: $('#gen-symbols').checked
    };
    const pass = generatePassword(length, options);
    $('#gen-output').textContent = pass;
    updateStrengthUI($('#gen-strength'), $('#gen-strength-label'), pass);
  }

  // ══════════════════════════════════
  //  INITIALIZATION
  // ══════════════════════════════════

  async function init() {
    initEventListeners();

    const exists = await vaultExists();
    if (!exists) {
      showScreen('screen-setup');
      setTimeout(() => $('#setup-password')?.focus(), 100);
      return;
    }

    // Check if local storage has the persistent key
    const sessData = await chrome.storage.local.get(['deadbolt_session_key', 'deadbolt_session_salt']);
    if (sessData.deadbolt_session_key && sessData.deadbolt_session_salt) {
      try {
        const keyBuffer = base64ToBuffer(sessData.deadbolt_session_key);
        const saltBuffer = base64ToBuffer(sessData.deadbolt_session_salt);
        state.cryptoKey = await crypto.subtle.importKey(
          'raw', keyBuffer, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );
        state.salt = new Uint8Array(saltBuffer);

        const data = await storageGet([STORAGE_KEYS.VAULT, STORAGE_KEYS.IV, STORAGE_KEYS.SETTINGS]);
        if (data[STORAGE_KEYS.VAULT] && data[STORAGE_KEYS.IV]) {
          state.entries = await decrypt(data[STORAGE_KEYS.VAULT], data[STORAGE_KEYS.IV], state.cryptoKey);
        } else {
          state.entries = [];
        }
        if (data[STORAGE_KEYS.SETTINGS]) {
          try { state.settings = JSON.parse(data[STORAGE_KEYS.SETTINGS]); } catch {}
        }
        
        showScreen('screen-vault');
        renderEntries();
        return; // Successfully resumed session
      } catch (e) {
        console.error("Session resume failed:", e);
        chrome.storage.local.set({ debug_error: e.message + '\n' + e.stack });
        sessionClear();
      }
    }

    showScreen('screen-login');
    // Focus the password field
    setTimeout(() => $('#login-password')?.focus(), 100);
  }

  // Start
  document.addEventListener('DOMContentLoaded', init);

})();
