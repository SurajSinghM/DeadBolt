let currentStep = 0;
const totalSteps = 5;

function nextStep() {
  if (currentStep < totalSteps - 1) {
    document.querySelectorAll('.step')[currentStep].classList.remove('active');
    currentStep++;
    document.getElementById('carousel').style.transform = `translateX(-${currentStep * 20}%)`;
    document.querySelectorAll('.step')[currentStep].classList.add('active');
  }
}

document.getElementById('btn-next-1').addEventListener('click', nextStep);
document.getElementById('btn-next-2').addEventListener('click', nextStep);
document.getElementById('btn-next-3').addEventListener('click', nextStep);
document.getElementById('btn-close').addEventListener('click', () => window.close());

// Password strength logic
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

  if (score <= 2) return { score, label: 'Weak', level: 'weak', pct: 25, color: '#ef4444' };
  if (score <= 3) return { score, label: 'Fair', level: 'fair', pct: 50, color: '#f59e0b' };
  if (score <= 5) return { score, label: 'Good', level: 'good', pct: 75, color: '#10b981' };
  return { score, label: 'Strong', level: 'strong', pct: 100, color: '#059669' };
}

document.getElementById('setup-password').addEventListener('input', (e) => {
  const s = calcPasswordStrength(e.target.value);
  const fill = document.getElementById('setup-strength');
  const label = document.getElementById('setup-strength-label');
  fill.style.width = s.pct + '%';
  fill.style.background = s.color || 'transparent';
  label.textContent = s.label;
  label.style.color = s.color || 'inherit';
});

document.getElementById('form-setup').addEventListener('submit', async (e) => {
  e.preventDefault();
  const pass = document.getElementById('setup-password').value;
  const conf = document.getElementById('setup-confirm').value;
  const error = document.getElementById('setup-error');
  
  if (pass !== conf) {
    error.textContent = 'Passwords do not match.';
    return;
  }
  if (calcPasswordStrength(pass).score <= 2) {
    error.textContent = 'Password is too weak.';
    return;
  }
  
  error.textContent = '';
  
  // ── Web Crypto API Utilities ──
  function getRandomBytes(length) { return crypto.getRandomValues(new Uint8Array(length)); }
  function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }
  async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true, ['encrypt', 'decrypt']
    );
  }
  async function encrypt(data, key) {
    const encoder = new TextEncoder();
    const iv = getRandomBytes(12);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(data)));
    return { ciphertext: bufferToBase64(encrypted), iv: bufferToBase64(iv) };
  }

  // Create vault and setup session
  try {
    const salt = getRandomBytes(32);
    const key = await deriveKey(pass, salt);
    
    const verifyData = await encrypt('DEADBOLT_VAULT_OK', key);
    const vaultData = await encrypt([], key);

    await chrome.storage.local.set({
      deadbolt_salt: bufferToBase64(salt),
      deadbolt_vault: vaultData.ciphertext,
      deadbolt_iv: vaultData.iv,
      deadbolt_verify: JSON.stringify(verifyData),
      deadbolt_settings: JSON.stringify({ autoLockMinutes: 5 })
    });
    
    // Save persistent session key
    const rawKey = await crypto.subtle.exportKey('raw', key);
    await chrome.storage.local.set({
      deadbolt_session_key: bufferToBase64(rawKey),
      deadbolt_session_salt: bufferToBase64(salt)
    });
    
    // Notify background script that vault is unlocked
    chrome.runtime.sendMessage({ action: 'vault-unlocked' });
    
    // Move to success step
    nextStep();
  } catch (err) {
    console.error(err);
    error.textContent = 'Failed to create vault.';
  }
});
