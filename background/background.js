/* ═══════════════════════════════════════════════════
   DeadBolt — Background Service Worker
   Manages badge state, message routing,
   and login form detection notifications
   (Mirrors Proton Pass background architecture)
   ═══════════════════════════════════════════════════ */

let isUnlocked = false;
const detectedLoginTabs = new Map();
const pendingSaves = new Map(); // tabId -> { hostname, url }
const contentScriptTokens = new Map(); // tabId -> token

function isTrustedOrigin(sender) {
  return sender.origin === `chrome-extension://${chrome.runtime.id}`;
}

// Purge any leaked session keys from persistent storage (Security Fix)
chrome.storage.local.remove(['deadbolt_session_key', 'deadbolt_session_salt']);

// ── Listen for messages from popup & content scripts ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  initStatePromise.then(() => {
    switch (message.action) {

      case 'get-status':
        sendResponse({ unlocked: isUnlocked });
        return true;

      case 'login-form-detected':
        // Content script detected a login form on the page
        if (sender.tab?.id) {
          detectedLoginTabs.set(sender.tab.id, {
            hostname: message.hostname,
            url: message.url
          });
          // Generate session token for content script
          const token = crypto.randomUUID();
          contentScriptTokens.set(sender.tab.id, token);

          // Update badge to show there's a login form on this tab
          if (isUnlocked) {
            updateTabBadge(sender.tab.id, true);
            checkPhishing(sender.tab, message.hostname);
          }
          sendResponse({ ok: true, token: token });
        } else {
          sendResponse({ ok: false });
        }
        break;

      case 'check-credentials-exist':
        (async () => {
          if (!message.hostname) return sendResponse({ exists: false });
          const encoder = new TextEncoder();
          const domain = message.hostname.replace(/^www\./, '');
          const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(domain));
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
          
          chrome.storage.local.get(['deadbolt_domain_hashes'], (res) => {
            const hashes = res.deadbolt_domain_hashes || [];
            sendResponse({ exists: hashes.includes(hashHex) });
          });
        })();
        return true;

      case 'request-autofill':
        // Content script icon was clicked — find matching credentials and autofill
        if (sender.tab?.id && contentScriptTokens.get(sender.tab.id) === message.token) {
          handleAutoFillRequest(sender.tab, message);
          sendResponse({ ok: true });
        } else {
          sendResponse({ ok: false, error: 'Invalid token' });
        }
        break;

      case 'check-login-tab':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        // Popup asks if current tab has a detected login form
        if (message.tabId && detectedLoginTabs.has(message.tabId)) {
          sendResponse({
            hasLogin: true,
            ...detectedLoginTabs.get(message.tabId)
          });
        } else {
          sendResponse({ hasLogin: false });
        }
        return true;

      case 'get-credential':
        // Content script requests a specific credential by ID (after user selection)
        if (isUnlocked && message.id && sender.tab?.id && contentScriptTokens.get(sender.tab.id) === message.token) {
          handleGetCredential(message.id, sendResponse);
          return true; // async response
        } else {
          sendResponse(null);
        }
        break;

      case 'generate-password':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        sendResponse({ password: generatePassword(16, { upper: true, lower: true, digits: true, symbols: true }) });
        return true;

      case 'generate-email-alias':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        chrome.storage.local.get(['deadbolt_settings'], async (res) => {
          try {
            let settings = {};
            if (res.deadbolt_settings) settings = JSON.parse(res.deadbolt_settings);
            
            if (!settings.simpleloginApiKey) {
              sendResponse({ error: 'SimpleLogin API Key not configured in Settings.' });
              return;
            }
            
            const response = await fetch('https://app.simplelogin.io/api/alias/random/new', {
              method: 'POST',
              headers: {
                'Authentication': settings.simpleloginApiKey,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ mode: 'uuid' })
            });
            
            if (!response.ok) {
              sendResponse({ error: `API Error: ${response.status} ${response.statusText}` });
              return;
            }
            
            const data = await response.json();
            sendResponse({ alias: data.alias });
          } catch (err) {
            sendResponse({ error: err.message });
          }
        });
        return true;

      case 'get-email-aliases':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        chrome.storage.local.get(['deadbolt_settings'], async (res) => {
          try {
            let settings = {};
            if (res.deadbolt_settings) settings = JSON.parse(res.deadbolt_settings);
            
            if (!settings.simpleloginApiKey) {
              sendResponse({ error: 'SimpleLogin API Key not configured in Settings.' });
              return;
            }
            
            const response = await fetch('https://app.simplelogin.io/api/v2/aliases?page_id=0', {
              method: 'GET',
              headers: {
                'Authentication': settings.simpleloginApiKey,
              }
            });
            
            if (!response.ok) {
              sendResponse({ error: `API Error: ${response.status} ${response.statusText}` });
              return;
            }
            
            const data = await response.json();
            sendResponse({ aliases: data.aliases });
          } catch (err) {
            sendResponse({ error: err.message });
          }
        });
        return true;

      case 'delete-email-alias':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        chrome.storage.local.get(['deadbolt_settings'], async (res) => {
          try {
            let settings = {};
            if (res.deadbolt_settings) settings = JSON.parse(res.deadbolt_settings);
            
            if (!settings.simpleloginApiKey) {
              sendResponse({ error: 'SimpleLogin API Key not configured in Settings.' });
              return;
            }
            
            if (!message.aliasId) {
              sendResponse({ error: 'Alias ID is required.' });
              return;
            }
            
            const response = await fetch(`https://app.simplelogin.io/api/aliases/${message.aliasId}`, {
              method: 'DELETE',
              headers: {
                'Authentication': settings.simpleloginApiKey,
              }
            });
            
            if (!response.ok) {
              let errorMsg = `API Error: ${response.status} ${response.statusText}`;
              try {
                const data = await response.json();
                if (data.error) errorMsg += ` - ${data.error}`;
              } catch (e) {}
              sendResponse({ error: errorMsg });
              return;
            }
            
            sendResponse({ success: true });
          } catch (err) {
            sendResponse({ error: err.message });
          }
        });
        return true;

      case 'save-captured-credential':
        if (sender.tab?.id && contentScriptTokens.get(sender.tab.id) === message.token) {
          pendingSaves.set(sender.tab.id, message.credential);
          sendResponse({ ok: true });
        } else {
          sendResponse({ ok: false, error: 'Invalid token' });
        }
        break;

      case 'check-pending-saves':
        if (sender.tab?.id && contentScriptTokens.get(sender.tab.id) === message.token && pendingSaves.has(sender.tab.id)) {
          const cred = pendingSaves.get(sender.tab.id);
          pendingSaves.delete(sender.tab.id);
          sendResponse({ credential: cred });
        } else {
          sendResponse({ credential: null });
        }
        return true;

      case 'confirm-save-credential':
        if (message.credential && sender.tab?.id && contentScriptTokens.get(sender.tab.id) === message.token) {
          if (isUnlocked) {
            handleSaveCredential(message.credential).then(() => sendResponse({ success: true }));
          } else {
            chrome.storage.local.get(['deadbolt_pending_vault_saves'], (res) => {
              const saves = res.deadbolt_pending_vault_saves || [];
              saves.push(message.credential);
              chrome.storage.local.set({ 'deadbolt_pending_vault_saves': saves }, () => {
                sendResponse({ success: true, pending: true });
              });
            });
          }
          return true;
        }
        sendResponse({ success: false });
        break;

      case 'unlock-vault':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        handleUnlockVault(message.password).then((success) => {
          sendResponse({ success });
        });
        return true;

      case 'vault-unlocked':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        isUnlocked = true;
        updateBadge(true);
        resetAutoLock();
        sendResponse({ success: true });
        break;

      case 'vault-locked':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        lockVault();
        sendResponse({ success: true });
        break;

      case 'update-autolock':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        if (message.minutes) {
          autoLockMinutes = message.minutes;
          if (isUnlocked) resetAutoLock();
        }
        sendResponse({ success: true });
        break;

      case 'update-privacy':
        if (!isTrustedOrigin(sender)) return sendResponse({ error: 'Unauthorized' });
        updateWebRtcPolicy(message.blockWebRtc);
        updateHttpsEnforcer(message.forceHttps);
        forceHttpsEnabled = !!message.forceHttps;
        sendResponse({ success: true });
        break;
    }
  });
  return true; // Always return true because we handle EVERYTHING asynchronously after initStatePromise
});

// ── Badge indicator ──
function updateBadge(unlocked) {
  if (unlocked) {
    chrome.action.setBadgeText({ text: '' });
    chrome.action.setBadgeBackgroundColor({ color: '#3fb950' });
  } else {
    chrome.action.setBadgeText({ text: '🔒' });
    chrome.action.setBadgeBackgroundColor({ color: '#484f58' });
  }
}

function updateTabBadge(tabId, hasLogin) {
  if (hasLogin && isUnlocked) {
    // Show a subtle indicator that credentials are available for this tab
    chrome.action.setBadgeText({ text: '•', tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#58a6ff', tabId });
  }
}

// ── Background Auto-Fill Logic ──
function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function bgDecrypt(ciphertext, iv, key) {
  const decoder = new TextDecoder();
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBuffer(iv) },
    key,
    base64ToBuffer(ciphertext)
  );
  return JSON.parse(decoder.decode(decrypted));
}

async function handleAutoFillRequest(tab, message) {
  try {
    if (!isUnlocked) {
      chrome.tabs.sendMessage(tab.id, { action: 'prompt-unlock' });
      return;
    }

    resetAutoLock(); // Reset auto-lock timer on activity

    const sessionData = await chrome.storage.session.get(['deadbolt_session_key']);
    if (!sessionData.deadbolt_session_key) return;

    const keyBuffer = base64ToBuffer(sessionData.deadbolt_session_key);
    const key = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const localData = await chrome.storage.local.get(['deadbolt_vault', 'deadbolt_iv']);
    if (!localData.deadbolt_vault || !localData.deadbolt_iv) return;

    const entries = await bgDecrypt(localData.deadbolt_vault, localData.deadbolt_iv, key);

    // Find matching entry for this domain
    const url = new URL(tab.url);
    const domain = url.hostname.replace(/^www\./, '');

    const matchingEntries = entries.filter(e => {
      if (!e.url) return false;
      try {
        const eUrl = new URL(e.url.startsWith('http') ? e.url : 'https://' + e.url);
        const eDomain = eUrl.hostname.replace(/^www\./, '');
        return domain === eDomain || domain.endsWith('.' + eDomain);
      } catch {
        return e.url.toLowerCase().includes(domain.toLowerCase());
      }
    });

    if (matchingEntries.length === 1 && message.formType !== 'REGISTER' && message.formType !== 'PASSWORD_CHANGE') {
      // Exactly 1 match -> autofill instantly (unless registering)
      const match = matchingEntries[0];
      chrome.tabs.sendMessage(tab.id, {
        action: 'autofill',
        username: match.username || '',
        password: match.password || ''
      });
    } else if (matchingEntries.length > 1 || message.formType === 'REGISTER' || message.formType === 'PASSWORD_CHANGE') {
      // Multiple matches or registration -> show dropdown
      chrome.tabs.sendMessage(tab.id, {
        action: 'show-dropdown',
        credentials: matchingEntries.map(e => ({
          id: e.id,
          title: e.title || 'Untitled',
          username: e.username || ''
        }))
      });
    } else {
      // Highlight the badge to let user know they need to create/find an entry
      updateTabBadge(tab.id, true);
    }
  } catch (err) {
    console.error("Auto-fill request failed:", err);
  }
}

async function handleGetCredential(id, sendResponse) {
  try {
    resetAutoLock(); // Reset auto-lock timer on activity
    const sessionData = await chrome.storage.session.get(['deadbolt_session_key']);
    if (!sessionData.deadbolt_session_key) return sendResponse(null);

    const keyBuffer = base64ToBuffer(sessionData.deadbolt_session_key);
    const key = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const localData = await chrome.storage.local.get(['deadbolt_vault', 'deadbolt_iv']);
    if (!localData.deadbolt_vault || !localData.deadbolt_iv) return sendResponse(null);

    const entries = await bgDecrypt(localData.deadbolt_vault, localData.deadbolt_iv, key);
    const entry = entries.find(e => e.id === id);

    if (entry) {
      sendResponse({ username: entry.username || '', password: entry.password || '' });
    } else {
      sendResponse(null);
    }
  } catch (err) {
    console.error("Get credential failed:", err);
    sendResponse(null);
  }
}

// ── Clean up when tabs are closed ──
chrome.tabs.onRemoved.addListener((tabId) => {
  detectedLoginTabs.delete(tabId);
  pendingSaves.delete(tabId);
});

// ── Clean up when tabs navigate away ──
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete' && pendingSaves.has(tabId)) {
    const cred = pendingSaves.get(tabId);
    chrome.tabs.sendMessage(tabId, { action: 'show-save-banner', credential: cred });
    pendingSaves.delete(tabId);
  }

  if (changeInfo.url) {
    detectedLoginTabs.delete(tabId);
  }
});

// ── Password Generator ──
const CHARSETS = {
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  lower: 'abcdefghijklmnopqrstuvwxyz',
  digits: '0123456789',
  symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

function generatePassword(length, options) {
  let charset = '';
  if (options.upper) charset += CHARSETS.upper;
  if (options.lower) charset += CHARSETS.lower;
  if (options.digits) charset += CHARSETS.digits;
  if (options.symbols) charset += CHARSETS.symbols;
  if (!charset) charset = CHARSETS.lower;

  // Rejection sampling to eliminate modulo bias
  const maxValid = 256 - (256 % charset.length);
  let password = '';
  while (password.length < length) {
    const array = new Uint8Array(length * 2);
    crypto.getRandomValues(array);
    for (let i = 0; i < array.length && password.length < length; i++) {
      if (array[i] < maxValid) {
        password += charset[array[i] % charset.length];
      }
    }
  }
  return password;
}

// ── Vault Append Logic ──
function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function bgEncrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const encoded = encoder.encode(typeof data === 'string' ? data : JSON.stringify(data));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  return {
    ciphertext: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv)
  };
}

async function handleSaveCredential(credential) {
  try {
    resetAutoLock(); // Reset auto-lock timer on activity
    const sessionData = await chrome.storage.session.get(['deadbolt_session_key']);
    if (!sessionData.deadbolt_session_key) return;

    const keyBuffer = base64ToBuffer(sessionData.deadbolt_session_key);
    // Need importKey for both decrypt and encrypt
    const key = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt', 'encrypt']
    );

    const localData = await chrome.storage.local.get(['deadbolt_vault', 'deadbolt_iv']);
    let entries = [];
    if (localData.deadbolt_vault && localData.deadbolt_iv) {
      entries = await bgDecrypt(localData.deadbolt_vault, localData.deadbolt_iv, key);
    }

    const newEntry = {
      id: crypto.randomUUID(),
      title: credential.hostname || new URL(credential.url).hostname,
      url: credential.url,
      username: credential.username,
      password: credential.password,
      notes: 'Auto-captured by DeadBolt',
      folder: '',
      tags: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    entries.push(newEntry);

    const newVault = await bgEncrypt(entries, key);
    await chrome.storage.local.set({
      'deadbolt_vault': newVault.ciphertext,
      'deadbolt_iv': newVault.iv
    });

    const encoder = new TextEncoder();
    let domain = '';
    try {
      domain = (credential.hostname || new URL(credential.url).hostname).replace(/^www\./, '');
    } catch(e) {}
    
    if (domain) {
      const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(domain));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      chrome.storage.local.get(['deadbolt_domain_hashes'], (res) => {
        const hashes = res.deadbolt_domain_hashes || [];
        if (!hashes.includes(hashHex)) {
          hashes.push(hashHex);
          chrome.storage.local.set({ 'deadbolt_domain_hashes': hashes });
        }
      });
    }
  } catch (err) {
    console.error("Failed to append credential:", err);
  }
}

// ── Vault Unlock Logic ──
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function handleUnlockVault(masterPassword) {
  try {
    const data = await chrome.storage.local.get(['deadbolt_salt', 'deadbolt_verify', 'deadbolt_pending_vault_saves']);
    if (!data.deadbolt_salt || !data.deadbolt_verify) return false;

    const salt = base64ToBuffer(data.deadbolt_salt);
    const key = await deriveKey(masterPassword, salt);

    const verifyData = JSON.parse(data.deadbolt_verify);
    const decoder = new TextDecoder();

    // Attempt decryption of verify phrase
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBuffer(verifyData.iv) },
      key,
      base64ToBuffer(verifyData.ciphertext)
    );

    const phrase = JSON.parse(decoder.decode(decrypted));
    if (phrase !== 'DEADBOLT_VAULT_OK') return false;

    // Successful unlock!
    const rawKey = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.session.set({
      deadbolt_session_key: bufferToBase64(rawKey),
      deadbolt_session_salt: bufferToBase64(salt)
    });

    isUnlocked = true;
    updateBadge(true);
    resetAutoLock();

    // Process any pending saves that were queued while locked
    if (data.deadbolt_pending_vault_saves && data.deadbolt_pending_vault_saves.length > 0) {
      for (const cred of data.deadbolt_pending_vault_saves) {
        await handleSaveCredential(cred);
      }
      chrome.storage.local.remove(['deadbolt_pending_vault_saves']);
    }

    return true;
  } catch (err) {
    console.error("Unlock failed:", err);
    return false;
  }
}

let forceHttpsEnabled = false;

// ── Privacy Enhancements ──
function updateWebRtcPolicy(block) {
  if (chrome.privacy && chrome.privacy.network && chrome.privacy.network.webRTCIPHandlingPolicy) {
    const policy = block ? 'disable_non_proxied_udp' : 'default';
    chrome.privacy.network.webRTCIPHandlingPolicy.set({ value: policy });
  }
}

async function updateHttpsEnforcer(enforce) {
  if (!chrome.declarativeNetRequest) return;
  const ruleId = 1;
  if (enforce) {
    await chrome.declarativeNetRequest.updateDynamicRules({
      addRules: [{
        "id": ruleId,
        "priority": 1,
        "action": { "type": "upgradeScheme" },
        "condition": {
          "urlFilter": "http://*",
          "resourceTypes": ["main_frame", "sub_frame"]
        }
      }],
      removeRuleIds: [ruleId]
    });
  } else {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [ruleId]
    });
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId === 0 && forceHttpsEnabled && details.url.startsWith('http://')) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: '/favicon logo/android-chrome-192x192.png',
      title: 'DeadBolt Security',
      message: 'HTTPS connection enforced',
      priority: 1
    });
  }
});

// ── Auto-Lock Logic ──
let autoLockMinutes = 5;

function resetAutoLock() {
  chrome.alarms.create('autolock', { delayInMinutes: autoLockMinutes });
}

function lockVault() {
  chrome.storage.session.remove(['deadbolt_session_key', 'deadbolt_session_salt']);
  isUnlocked = false;
  updateBadge(false);
  chrome.alarms.clear('autolock');
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'autolock') {
    lockVault();
  }
});

// ── Initial state ──
let initStatePromise = new Promise((resolve) => {
  chrome.storage.local.get(['deadbolt_settings'], (localRes) => {
    chrome.storage.session.get(['deadbolt_session_key'], (sessionRes) => {
      if (sessionRes.deadbolt_session_key) {
        isUnlocked = true;
        updateBadge(true);
        resetAutoLock();
      } else {
        updateBadge(false);
      }

      // Initialize settings
      if (localRes.deadbolt_settings) {
        try {
          const settings = JSON.parse(localRes.deadbolt_settings);
          if (settings.autoLockMinutes) autoLockMinutes = settings.autoLockMinutes;
          updateWebRtcPolicy(settings.blockWebRtc);
          updateHttpsEnforcer(settings.forceHttps);
          forceHttpsEnabled = !!settings.forceHttps;
        } catch { }
      }
      
      resolve();
    });
  });
});

// ── Handle install/update ──
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('onboarding/onboarding.html') });
  }
});
// ── Anti-Phishing Logic ──
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = Array.from({ length: a.length + 1 }, () =>
    new Array(b.length + 1).fill(0)
  );

  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,      // deletion
        matrix[i][j - 1] + 1,      // insertion
        matrix[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return matrix[a.length][b.length];
}

async function checkPhishing(tab, currentHostname) {
  try {
    const sessionData = await chrome.storage.session.get(['deadbolt_session_key']);
    if (!sessionData.deadbolt_session_key) return;

    const keyBuffer = base64ToBuffer(sessionData.deadbolt_session_key);
    const key = await crypto.subtle.importKey(
      'raw', keyBuffer, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );

    const localData = await chrome.storage.local.get(['deadbolt_vault', 'deadbolt_iv']);
    if (!localData.deadbolt_vault || !localData.deadbolt_iv) return;

    const entries = await bgDecrypt(localData.deadbolt_vault, localData.deadbolt_iv, key);

    let isExactMatch = false;
    let closestMatch = null;
    let minDistance = Infinity;

    const cleanHost = currentHostname.replace(/^www\./, '').toLowerCase();

    for (const entry of entries) {
      if (!entry.url) continue;

      let savedHost = '';
      try {
        const u = new URL(entry.url.startsWith('http') ? entry.url : 'https://' + entry.url);
        savedHost = u.hostname.replace(/^www\./, '').toLowerCase();
      } catch { continue; }

      if (!savedHost) continue;

      if (cleanHost === savedHost || cleanHost.endsWith('.' + savedHost)) {
        isExactMatch = true;
        break;
      }

      const dist = levenshteinDistance(cleanHost, savedHost);
      // Flag distance 1 or 2 as phishing for domains > 4 chars
      if (dist > 0 && dist <= 2 && savedHost.length > 4) {
        if (dist < minDistance) {
          minDistance = dist;
          closestMatch = savedHost;
        }
      }
    }

    if (!isExactMatch && closestMatch) {
      chrome.tabs.sendMessage(tab.id, {
        action: 'phishing-alert',
        suspiciousDomain: cleanHost,
        safeDomain: closestMatch
      });
    }
  } catch (err) {
    console.error("Phishing check failed:", err);
  }
}
