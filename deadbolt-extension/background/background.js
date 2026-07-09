/* ═══════════════════════════════════════════════════
   DeadBolt — Background Service Worker
   Manages badge state, message routing,
   and login form detection notifications
   (Mirrors Proton Pass background architecture)
   ═══════════════════════════════════════════════════ */

let isUnlocked = false;
const detectedLoginTabs = new Map();
const pendingSaves = new Map(); // tabId -> { hostname, url }

// ── Listen for messages from popup & content scripts ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  initStatePromise.then(() => {
    switch (message.action) {
    case 'vault-unlocked':
      isUnlocked = true;
      updateBadge(true);
      break;

    case 'vault-locked':
      isUnlocked = false;
      updateBadge(false);
      detectedLoginTabs.clear();
      chrome.storage.local.remove(['deadbolt_session_key', 'deadbolt_session_salt']);
      break;

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
        // Update badge to show there's a login form on this tab
        if (isUnlocked) {
          updateTabBadge(sender.tab.id, true);
          checkPhishing(sender.tab, message.hostname);
        }
      }
      break;

    case 'request-autofill':
      // Content script icon was clicked — find matching credentials and autofill
      if (sender.tab?.id && isUnlocked) {
        handleAutoFillRequest(sender.tab, message);
      }
      break;

    case 'check-login-tab':
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
      if (isUnlocked && message.id) {
        handleGetCredential(message.id, sendResponse);
        return true; // async response
      } else {
        sendResponse(null);
      }
      break;

    case 'generate-password':
      sendResponse({ password: generatePassword(16, { upper: true, lower: true, digits: true, symbols: true }) });
      return true;

    case 'save-captured-credential':
      if (sender.tab?.id) {
        pendingSaves.set(sender.tab.id, message.credential);
      }
      sendResponse({ ok: true });
      break;

    case 'check-pending-saves':
      if (sender.tab?.id && pendingSaves.has(sender.tab.id)) {
        const cred = pendingSaves.get(sender.tab.id);
        pendingSaves.delete(sender.tab.id);
        sendResponse({ credential: cred });
      } else {
        sendResponse({ credential: null });
      }
      return true;

    case 'confirm-save-credential':
      if (isUnlocked && message.credential) {
        handleSaveCredential(message.credential).then(() => sendResponse({ success: true }));
        return true;
      }
      sendResponse({ success: false });
      break;

    case 'unlock-vault':
      handleUnlockVault(message.password).then((success) => {
        sendResponse({ success });
      });
      return true;
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

    const sessionData = await chrome.storage.local.get(['deadbolt_session_key']);
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
    const sessionData = await chrome.storage.local.get(['deadbolt_session_key']);
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

  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[array[i] % charset.length];
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
    const sessionData = await chrome.storage.local.get(['deadbolt_session_key']);
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
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    entries.push(newEntry);
    
    const newVault = await bgEncrypt(entries, key);
    await chrome.storage.local.set({
      'deadbolt_vault': newVault.ciphertext,
      'deadbolt_iv': newVault.iv
    });
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
    const data = await chrome.storage.local.get(['deadbolt_salt', 'deadbolt_verify']);
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
    
    const phrase = decoder.decode(decrypted);
    if (phrase !== 'DEADBOLT_VAULT_OK') return false;

    // Successful unlock!
    const rawKey = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.local.set({
      deadbolt_session_key: bufferToBase64(rawKey),
      deadbolt_session_salt: bufferToBase64(salt)
    });
    
    isUnlocked = true;
    updateBadge(true);
    
    return true;
  } catch (err) {
    console.error("Unlock failed:", err);
    return false;
  }
}

// ── Initial state ──
let initStatePromise = new Promise((resolve) => {
  chrome.storage.local.get(['deadbolt_session_key'], (res) => {
    if (res.deadbolt_session_key) {
      isUnlocked = true;
      updateBadge(true);
    } else {
      updateBadge(false);
    }
    resolve();
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
    const sessionData = await chrome.storage.local.get(['deadbolt_session_key']);
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
