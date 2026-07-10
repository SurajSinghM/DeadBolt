document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('unlock-form');
  const input = document.getElementById('password-input');
  const error = document.getElementById('error-msg');
  const btn = document.getElementById('unlock-btn');

  input.focus();

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const pw = input.value;
    if (!pw) return;

    btn.textContent = '...';
    btn.disabled = true;
    error.style.display = 'none';

    chrome.runtime.sendMessage({ action: 'unlock-vault', password: pw }, (res) => {
      if (res && res.success) {

        window.parent.postMessage({ type: 'DEADBOLT_UNLOCKED' }, '*');
      } else {
        btn.textContent = 'Unlock';
        btn.disabled = false;
        error.style.display = 'block';
        input.value = '';
        input.focus();
      }
    });
  });

  document.addEventListener('click', (e) => {
    if (e.target === document.body) {
      window.parent.postMessage({ type: 'DEADBOLT_DISMISS_UNLOCK' }, '*');
    }
  });
});
