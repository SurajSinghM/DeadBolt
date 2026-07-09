/* ═══════════════════════════════════════════════════
   DeadBolt — Content Script
   Advanced login form detection & auto-fill engine
   Inspired by Proton Pass orchestrator architecture:
   - ML-style form classification (LOGIN, REGISTER, RECOVERY, etc.)
   - Multilingual regex field detection
   - Shadow DOM icon injection (style-resistant)
   - MutationObserver for SPA support
   - Native input value setter for framework compatibility
   ═══════════════════════════════════════════════════ */

(() => {
  'use strict';

  // Prevent double-injection
  if (window.__deadboltInjected) return;
  window.__deadboltInjected = true;

  // ══════════════════════════════════
  //  FORM TYPE CLASSIFICATION
  //  (Mirrors Proton Pass FormType enum)
  // ══════════════════════════════════

  const FormType = {
    LOGIN: 'login',
    REGISTER: 'register',
    PASSWORD_CHANGE: 'password-change',
    RECOVERY: 'recovery',
    NOOP: 'noop'
  };

  const FieldType = {
    EMAIL: 'email',
    USERNAME: 'username',
    USERNAME_HIDDEN: 'username-hidden',
    PASSWORD_CURRENT: 'password',
    PASSWORD_NEW: 'new-password',
    OTP: 'otp'
  };

  // ══════════════════════════════════
  //  MULTILINGUAL REGEX PATTERNS
  //  (Derived from Proton Pass orchestrator)
  // ══════════════════════════════════

  const RE = {
    // Password-related terms (multi-language)
    PASSWORD: /p(?:hrasesecrete|ass(?:(?:phras|cod)e|wor[dt]))|(?:c(?:havesecret|lavesecret|ontrasen)|deseguranc)a|(?:(?:zugangs|secret)cod|clesecret)e|wachtwoord|codesecret|motdepasse|geheimnis|secret|heslo|senha|key/i,

    // Username-related terms
    USERNAME: /gebruikersnaam|(?:identifi(?:cado|e)|benutze)r|identi(?:fiant|ty)|u(?:tilisateur|s(?:ername|uario))|(?:screen|nick)name|nutzername|(?:anmeld|handl)e|pseudo/i,

    // Email-related terms
    EMAIL: /co(?:urriel|rrei?o)|email/i,

    // Confirm / re-type patterns
    CONFIRM: /digitarnovamente|v(?:olveraescribi|erifi(?:ca|e))r|saisiranouveau|(?:erneuteingeb|wiederhol|bestatig)en|verif(?:izieren|y)|re(?:pe(?:t[ei]r|at)|type)|confirm|again/i,

    // Second field indicator
    SECOND: /\b\S*(?:snd|bis|2)\b/i,

    // 2FA / OTP patterns
    MFA: /(?:doublefacteu|(?:doblefac|zweifak|twofac)to)r|verifica(?:c(?:ion|ao)|tion)|multifa(?:ct(?:eu|o)|k?to)r|(?:securitycod|doubleetap|authcod)e|zweischritte|dois(?:fatore|passo)s|doblepaso|2(?:s(?:chritte|tep)|(?:etap[ae]|paso)s|fa)|twostep/i,
    OTP: /(?:authentication|approvals|email|login)code|phoneverification|challenge|t(?:wo(?:fa(?:ctor)?|step)|facode)|2fa|\b([mt]fa)\b/i,
    OTP_TOKEN: /totp(?:pin)?|o(?:netime|t[cp])|1time/i,

    // Recovery / forgot password
    RECOVERY: /schwierigkeit|(?:difficult|troubl|oubli|hilf)e|i(?:nciden(?:cia|t)|ssue)|vergessen|esquecido|olvidado|needhelp|questao|problem|forgot|ayuda/i,

    // Progress / step indicators
    STEP: /p(?:rogres(?:s(?:ion|o)|o)|aso)|fortschritt|progress|s(?:chritt|t(?:age|ep))|etap[ae]|phase/i,

    // Newsletter / marketing (to ignore)
    NEWSLETTER: /newsletter|b(?:ul|o)letin|mailing/i,

    // Register / sign-up page indicators
    REGISTER: /regist(?:ration|er|rieren)|anmeld(?:en|ung)|s(?:ubscri(?:be|ption)|ign.?up|crivers|inscrire)|inscription|create.?account|new.?account|open.?account|join|enroll/i,

    // Login / sign-in page indicators
    LOGIN: /log.?(?:in|on)|sign.?in|anmelden|einloggen|iniciar.?ses|connexion|enter|authenticate|auth/i,

    // Credit card (to exclude)
    CREDIT_CARD: /(?:payments?|new)card|c(?:ar(?:tecredit|d)|red(?:it(?:debit|card)|card))|stripe|vads/i,

    // Search fields (to exclude)
    SEARCH: /search|busca|cherch|suche|zoek|szuk|recherch/i
  };

  // ══════════════════════════════════
  //  VISIBILITY & DOM UTILITIES
  //  (Mirrors Proton Pass isVisible)
  // ══════════════════════════════════

  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();

    // Check computed styles
    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;

    // Check dimensions
    if (rect.width === 0 && rect.height === 0 && style.overflow === 'hidden') return false;

    // Check if off-screen
    if (rect.x + rect.width < 0 || rect.y + rect.height < 0) return false;

    // Check ancestors for opacity: 0 or display: none
    let parent = el.parentElement;
    while (parent) {
      const ps = window.getComputedStyle(parent);
      if (ps.opacity === '0' || ps.display === 'none') return false;
      if (ps.display === 'contents') { parent = parent.parentElement; continue; }
      parent = parent.parentElement;
    }

    return true;
  }

  function isHiddenInput(el) {
    return el.type === 'hidden' ||
           el.getAttribute('aria-hidden') === 'true' ||
           !isVisible(el);
  }

  // Get attributes for matching — concatenate name, id, placeholder, autocomplete, aria-label, label text
  function getFieldFingerprint(field) {
    const parts = [
      field.name || '',
      field.id || '',
      field.placeholder || '',
      field.autocomplete || '',
      field.getAttribute('aria-label') || '',
      field.getAttribute('data-testid') || '',
      field.className || ''
    ];

    // Check for associated <label>
    if (field.id) {
      const label = field.ownerDocument.querySelector(`label[for="${field.id}"]`);
      if (label) parts.push(label.textContent || '');
    }

    // Check for wrapping <label>
    const wrappingLabel = field.closest('label');
    if (wrappingLabel) parts.push(wrappingLabel.textContent || '');

    return parts.map(s => s.trim().toLowerCase().replace(/\s+/g, '')).join('|');
  }

  // ══════════════════════════════════
  //  FIELD CLASSIFICATION
  //  (Mirrors Proton Pass FieldType detection)
  // ══════════════════════════════════

  function classifyField(field) {
    const type = (field.type || '').toLowerCase();
    const fingerprint = getFieldFingerprint(field);
    const autocomplete = (field.autocomplete || '').toLowerCase();

    // Explicit type=password
    if (type === 'password') {
      // Is it a "new" password or "current" password?
      if (autocomplete === 'new-password' || RE.CONFIRM.test(fingerprint) || RE.SECOND.test(fingerprint)) {
        return FieldType.PASSWORD_NEW;
      }
      return FieldType.PASSWORD_CURRENT;
    }

    // Skip search fields
    if (type === 'search' || RE.SEARCH.test(fingerprint)) return null;

    // Skip credit card fields
    if (RE.CREDIT_CARD.test(fingerprint)) return null;

    // Skip newsletter/subscription checkboxes
    if (RE.NEWSLETTER.test(fingerprint)) return null;

    // Skip file, button, submit, reset, checkbox, radio, image, hidden, range, color
    if (['file', 'button', 'submit', 'reset', 'checkbox', 'radio', 'image', 'hidden', 'range', 'color', 'date', 'datetime-local', 'month', 'week', 'time'].includes(type)) {
      return null;
    }

    // Explicit autocomplete hints
    if (autocomplete === 'username' || autocomplete === 'email') return FieldType.EMAIL;
    if (autocomplete === 'one-time-code') return FieldType.OTP;

    // OTP detection
    if (RE.OTP.test(fingerprint) || RE.OTP_TOKEN.test(fingerprint) || RE.MFA.test(fingerprint)) {
      return FieldType.OTP;
    }

    // Email detection
    if (type === 'email' || RE.EMAIL.test(fingerprint)) return FieldType.EMAIL;

    // Username detection
    if (RE.USERNAME.test(fingerprint)) return FieldType.USERNAME;

    // tel type might be phone/sms for OTP
    if (type === 'tel') {
      if (RE.OTP.test(fingerprint) || RE.MFA.test(fingerprint)) return FieldType.OTP;
      return null;
    }

    // Text or untyped inputs near a password field are likely usernames
    if (type === 'text' || type === '') {
      return FieldType.USERNAME;
    }

    return null;
  }

  // ══════════════════════════════════
  //  FORM CLASSIFICATION
  //  (Mirrors Proton Pass FormType detection)
  // ══════════════════════════════════

  function classifyForm(form, fields) {
    const passwordFields = fields.filter(f => f.fieldType === FieldType.PASSWORD_CURRENT || f.fieldType === FieldType.PASSWORD_NEW);
    const newPasswords = fields.filter(f => f.fieldType === FieldType.PASSWORD_NEW);
    const currentPasswords = fields.filter(f => f.fieldType === FieldType.PASSWORD_CURRENT);
    const usernameFields = fields.filter(f => f.fieldType === FieldType.EMAIL || f.fieldType === FieldType.USERNAME);
    const otpFields = fields.filter(f => f.fieldType === FieldType.OTP);

    // If no password and no username fields, it's not an auth form
    if (passwordFields.length === 0 && usernameFields.length === 0 && otpFields.length === 0) {
      return FormType.NOOP;
    }

    // Get page-level context clues
    const pageText = (document.title + ' ' + window.location.href).toLowerCase();
    const formFingerprint = form ? getFormFingerprint(form) : '';

    // Recovery form — no password, has username, page mentions forgot/trouble
    if (passwordFields.length === 0 && usernameFields.length > 0 && otpFields.length === 0) {
      if (RE.RECOVERY.test(pageText) || RE.RECOVERY.test(formFingerprint)) {
        return FormType.RECOVERY;
      }
    }

    // OTP-only form
    if (otpFields.length > 0 && passwordFields.length === 0) {
      return FormType.NOOP; // Not a form we fill with username/password
    }

    // Register: has new-password fields, or multiple password fields (password + confirm), or page says "register"
    if (newPasswords.length > 0 || passwordFields.length >= 2 ||
        RE.REGISTER.test(pageText) || RE.REGISTER.test(formFingerprint)) {
      return FormType.REGISTER;
    }

    // Password change: multiple password fields with current + new
    if (currentPasswords.length >= 1 && passwordFields.length >= 2) {
      return FormType.PASSWORD_CHANGE;
    }

    // Login: has a password and a username/email field (or just a password)
    if (passwordFields.length >= 1) {
      return FormType.LOGIN;
    }

    // Username-only (first step of multi-step login)
    if (usernameFields.length > 0) {
      if (RE.LOGIN.test(pageText) || RE.LOGIN.test(formFingerprint)) {
        return FormType.LOGIN;
      }
    }

    return FormType.NOOP;
  }

  function getFormFingerprint(form) {
    return [
      form.id || '',
      form.name || '',
      form.className || '',
      form.action || '',
      form.getAttribute('aria-label') || ''
    ].join('|').toLowerCase();
  }

  // ══════════════════════════════════
  //  FORM DETECTION ENGINE
  //  Scans the DOM for login/register forms
  // ══════════════════════════════════

  function detectForms() {
    const detectedForms = [];

    // Strategy 1: Find all <form> elements containing password or username fields
    const forms = document.querySelectorAll('form');
    const processedInputs = new Set();

    forms.forEach(form => {
      const inputs = Array.from(form.querySelectorAll('input'));
      const classifiedFields = [];

      inputs.forEach(input => {
        if (isHiddenInput(input) || processedInputs.has(input)) return;
        const fieldType = classifyField(input);
        if (fieldType) {
          classifiedFields.push({ element: input, fieldType });
          processedInputs.add(input);
        }
      });

      if (classifiedFields.length > 0) {
        const formType = classifyForm(form, classifiedFields);
        if (formType !== FormType.NOOP) {
          detectedForms.push({ form, formType, fields: classifiedFields });
        }
      }
    });

    // Strategy 2: Find orphan password/username inputs not inside a <form>
    const allInputs = document.querySelectorAll('input');
    const orphanFields = [];

    allInputs.forEach(input => {
      if (processedInputs.has(input) || isHiddenInput(input) || input.closest('form')) return;
      const fieldType = classifyField(input);
      if (fieldType) {
        orphanFields.push({ element: input, fieldType });
        processedInputs.add(input);
      }
    });

    if (orphanFields.length > 0) {
      // Group orphan fields by proximity (common ancestor container)
      const groups = groupOrphanFields(orphanFields);
      groups.forEach(group => {
        const formType = classifyForm(null, group);
        if (formType !== FormType.NOOP) {
          detectedForms.push({ form: null, formType, fields: group });
        }
      });
    }

    return detectedForms;
  }

  function groupOrphanFields(fields) {
    if (fields.length <= 1) return [fields];

    // Group by closest common container (div, section, etc.)
    const groups = [];
    const used = new Set();

    fields.forEach(field => {
      if (used.has(field)) return;

      const group = [field];
      used.add(field);

      // Find nearby fields (within a reasonable DOM distance)
      const container = findFormLikeContainer(field.element);
      if (container) {
        fields.forEach(other => {
          if (used.has(other)) return;
          if (container.contains(other.element)) {
            group.push(other);
            used.add(other);
          }
        });
      }

      groups.push(group);
    });

    return groups;
  }

  function findFormLikeContainer(el) {
    let current = el.parentElement;
    let depth = 0;
    while (current && depth < 8) {
      const tag = current.tagName;
      // Stop at common container elements
      if (['SECTION', 'MAIN', 'ARTICLE', 'BODY'].includes(tag)) return current;
      // Check if it looks like a form container
      const role = current.getAttribute('role');
      if (role === 'form' || role === 'dialog' || role === 'main') return current;
      // DIVs with form-like classes
      const cls = (current.className || '').toLowerCase();
      if (/form|login|auth|sign|modal|card|panel|container/i.test(cls)) return current;
      current = current.parentElement;
      depth++;
    }
    return current || el.parentElement;
  }

  // ══════════════════════════════════
  //  SHADOW DOM ICON INJECTION
  //  (Mirrors Proton Pass ProtonPassControl custom element)
  //  Injects a DeadBolt icon inside password/username fields
  //  using Shadow DOM to resist external style overrides
  // ══════════════════════════════════

  const injectedFields = new WeakSet();
  let activeDropdownHost = null;
  let lastClickedField = null;
  let lastClickedFormType = null;

  function injectIcons(detectedForms) {
    detectedForms.forEach(({ formType, fields }) => {
      if (![FormType.LOGIN, FormType.REGISTER, FormType.PASSWORD_CHANGE].includes(formType)) return;

      fields.forEach(({ element: field, fieldType }) => {
        if (injectedFields.has(field)) return;
        if (fieldType === FieldType.OTP) return;

        injectFieldIcon(field, formType);
        injectedFields.add(field);
      });
      
      const anyField = fields[0]?.element;
      if (anyField) {
        attachSubmitListener(anyField, formType);
      }
    });
  }

  function attachSubmitListener(field, formType) {
    const form = field.closest('form');
    if (!form || form.hasAttribute('data-deadbolt-listener')) return;
    
    form.setAttribute('data-deadbolt-listener', 'true');
    form.addEventListener('submit', () => {
      const pwFields = Array.from(form.querySelectorAll('input[type="password"]')).filter(isVisible);
      if (pwFields.length === 0 || !pwFields[0].value) return;
      
      const userFields = Array.from(form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')).filter(isVisible);
      const username = userFields.length > 0 ? userFields[0].value : '';
      
      chrome.runtime.sendMessage({
        action: 'save-captured-credential',
        credential: {
          hostname: window.location.hostname,
          url: window.location.href,
          username,
          password: pwFields[0].value
        }
      });
      
      setTimeout(() => {
        chrome.runtime.sendMessage({ action: 'check-pending-saves' }, (res) => {
          if (res?.credential) renderSavePrompt(res.credential);
        });
      }, 1500);
    });
  }

  function injectFieldIcon(field, formType) {
    // Create a shadow DOM host element (like Proton Pass's custom elements)
    const host = document.createElement('deadbolt-icon');
    const shadow = host.attachShadow({ mode: 'closed' });

    // Shadow DOM CSS — completely isolated from page styles
    const style = document.createElement('style');
    style.textContent = `
      :host {
        position: absolute !important;
        pointer-events: none;
        width: 0 !important;
        height: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
        border: none !important;
        overflow: visible !important;
        z-index: 2147483647 !important;
        opacity: 1 !important;
        float: left !important;
        animation: none !important;
      }
      button {
        pointer-events: all;
        position: absolute;
        cursor: pointer;
        width: 24px;
        height: 24px;
        margin: auto;
        top: 0;
        bottom: 0;
        background: linear-gradient(135deg, #58a6ff 0%, #a371f7 100%);
        border: none;
        border-radius: 5px;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        max-width: 0;
        transition: opacity 0.15s ease, max-width 0.15s ease;
        box-shadow: 0 2px 6px rgba(88, 166, 255, 0.3);
      }
      button.visible {
        opacity: 0.85;
        max-width: 28px;
      }
      button:hover {
        opacity: 1;
        box-shadow: 0 3px 10px rgba(88, 166, 255, 0.4);
        transform: scale(1.05);
      }
      button svg {
        width: 14px;
        height: 14px;
        color: #fff;
        flex-shrink: 0;
      }
    `;

    const button = document.createElement('button');
    button.title = 'Fill with DeadBolt';
    button.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`;

    shadow.appendChild(style);
    shadow.appendChild(button);

    // Position the icon inside the field
    const positionIcon = () => {
      const rect = field.getBoundingClientRect();
      const parent = field.offsetParent || field.parentElement;
      if (!parent) return;

      const computedStyle = window.getComputedStyle(field);
      const fieldHeight = rect.height;

      // Position to the right inside the input
      host.style.position = 'absolute';
      
      const size = Math.min(24, fieldHeight - 8);
      // Place it 8px from the right inner edge of the field
      button.style.left = (field.offsetLeft + field.offsetWidth - size - 8) + 'px';
      button.style.right = 'auto';
      button.style.top = (field.offsetTop + (fieldHeight - size) / 2) + 'px';
      button.style.bottom = 'auto';
      button.style.height = size + 'px';
      button.style.width = size + 'px';
      button.style.margin = '0'; // Override previous auto margin

      // Inject padding so text doesn't overlap the icon
      const computedPadding = parseInt(computedStyle.paddingRight || '0', 10);
      if (computedPadding < size + 16) {
        field.style.paddingRight = (size + 16) + 'px';
      }

      // Make button visible after positioning
      requestAnimationFrame(() => button.classList.add('visible'));
    };

    // Insert the icon host as sibling of the input
    const parent = field.parentElement;
    if (parent) {
      const parentPos = window.getComputedStyle(parent).position;
      if (parentPos === 'static') {
        parent.style.position = 'relative';
      }
      // Insert after the field
      field.insertAdjacentElement('afterend', host);
      positionIcon();

      // Re-position on resize
      const resizeObserver = new ResizeObserver(positionIcon);
      resizeObserver.observe(field);
    }

    // Click handler: attempt to find matching credentials and fill
    button.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();

      lastClickedField = field;
      lastClickedFormType = formType;

      // Send message to background to check for matching credentials
      chrome.runtime.sendMessage({
        action: 'request-autofill',
        url: window.location.href,
        hostname: window.location.hostname,
        formType: formType
      });
    });

    // Also listen for focusin to show/hide
    field.addEventListener('focus', () => button.classList.add('visible'));
    field.addEventListener('blur', () => {
      setTimeout(() => button.classList.remove('visible'), 200);
    });

    // Start hidden, show on hover over parent or focus
    button.classList.remove('visible');
    if (parent) {
      parent.addEventListener('mouseenter', () => button.classList.add('visible'));
      parent.addEventListener('mouseleave', () => {
        if (document.activeElement !== field) button.classList.remove('visible');
      });
    }
  }

  // ══════════════════════════════════
  //  MULTI-ACCOUNT DROPDOWN
  // ══════════════════════════════════

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function renderDropdown(credentials, anchorField) {
    if (activeDropdownHost) {
      activeDropdownHost.remove();
    }

    const host = document.createElement('deadbolt-dropdown');
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host {
        position: absolute !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
        width: 0 !important;
        height: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
      }
      .dropdown-container {
        position: absolute;
        top: 8px;
        left: 0;
        width: max-content;
        min-width: 200px;
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1), 0 8px 10px -6px rgba(0,0,0,0.1);
        font-family: 'Inter', -apple-system, sans-serif;
        padding: 4px;
        pointer-events: all;
        opacity: 0;
        transform: translateY(-5px);
        transition: opacity 0.15s ease, transform 0.15s ease;
      }
      .dropdown-container.visible {
        opacity: 1;
        transform: translateY(0);
      }
      .dropdown-header {
        font-size: 11px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        color: #94a3b8;
        padding: 8px 12px 4px;
      }
      .dropdown-item {
        display: flex;
        flex-direction: column;
        padding: 8px 12px;
        cursor: pointer;
        border-radius: 6px;
        transition: background-color 0.1s ease;
        text-align: left;
      }
      .dropdown-item:hover {
        background-color: #fff7ed;
      }
      .dropdown-item .title {
        font-size: 14px;
        font-weight: 600;
        color: #0f172a;
        margin-bottom: 2px;
      }
      .dropdown-item .username {
        font-size: 12px;
        color: #64748b;
      }
    `;

    const container = document.createElement('div');
    container.className = 'dropdown-container';

    const header = document.createElement('div');
    header.className = 'dropdown-header';
    header.textContent = 'Select Account';
    container.appendChild(header);

    credentials.forEach(cred => {
      const item = document.createElement('div');
      item.className = 'dropdown-item';
      item.innerHTML = `
        <div class="title">${escapeHtml(cred.title)}</div>
        <div class="username">${escapeHtml(cred.username || 'No username')}</div>
      `;
      item.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        // Fetch full credential from background
        chrome.runtime.sendMessage({ action: 'get-credential', id: cred.id }, (response) => {
          if (response) {
            performAutofill(response.username, response.password);
          }
        });
        
        host.remove();
        activeDropdownHost = null;
      });
      container.appendChild(item);
    });

    if (lastClickedFormType === FormType.REGISTER || lastClickedFormType === FormType.PASSWORD_CHANGE) {
      if (credentials.length > 0) {
        const divider = document.createElement('div');
        divider.style.cssText = 'height: 1px; background: #e2e8f0; margin: 4px 0;';
        container.appendChild(divider);
      }
      const genItem = document.createElement('div');
      genItem.className = 'dropdown-item';
      genItem.innerHTML = `<div class="title" style="color: #f97316;">✨ Generate Secure Password</div>`;
      genItem.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        chrome.runtime.sendMessage({ action: 'generate-password' }, (response) => {
          if (response && response.password) {
            performAutofill('', response.password);
          }
        });
        
        host.remove();
        activeDropdownHost = null;
      });
      container.appendChild(genItem);
    }

    shadow.appendChild(style);
    shadow.appendChild(container);

    // Position it under the anchorField
    const parent = anchorField.parentElement;
    if (parent) {
      anchorField.insertAdjacentElement('afterend', host);
      
      // Calculate absolute positioning relative to anchorField
      host.style.position = 'absolute';
      
      const anchorRect = anchorField.getBoundingClientRect();
      // Dropdown appears right below the field, aligned to its left edge
      container.style.top = (anchorField.offsetTop + anchorRect.height + 4) + 'px';
      container.style.left = anchorField.offsetLeft + 'px';

      requestAnimationFrame(() => container.classList.add('visible'));
      activeDropdownHost = host;
    }
  }

  // Close dropdown on click outside
  document.addEventListener('click', (e) => {
    if (activeDropdownHost) {
      const path = e.composedPath();
      if (!path.includes(activeDropdownHost)) {
        activeDropdownHost.remove();
        activeDropdownHost = null;
      }
    }
  });

  // ══════════════════════════════════
  //  SAVE PROMPT UI
  // ══════════════════════════════════

  function renderSavePrompt(credential) {
    if (!credential) return;
    const host = document.createElement('deadbolt-save-prompt');
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host {
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        z-index: 2147483647 !important;
        pointer-events: none !important;
      }
      .toast {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        box-shadow: 0 10px 25px -5px rgba(0,0,0,0.2);
        font-family: 'Inter', -apple-system, sans-serif;
        padding: 16px;
        pointer-events: all;
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 300px;
        animation: slideIn 0.3s ease-out forwards;
      }
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      .title { font-weight: 600; color: #0f172a; font-size: 14px; }
      .desc { font-size: 13px; color: #64748b; margin: 0; }
      .buttons { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }
      button {
        padding: 6px 12px; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; border: none; transition: opacity 0.2s;
      }
      button:hover { opacity: 0.9; }
      .btn-cancel { background: #f1f5f9; color: #475569; }
      .btn-save { background: #f97316; color: white; }
    `;

    const container = document.createElement('div');
    container.className = 'toast';
    container.innerHTML = `
      <div class="title">Save Login</div>
      <p class="desc">Save password for <b>${escapeHtml(credential.hostname)}</b> to DeadBolt?</p>
      <div class="buttons">
        <button class="btn-cancel">Never</button>
        <button class="btn-save">Save</button>
      </div>
    `;

    container.querySelector('.btn-cancel').addEventListener('click', () => host.remove());
    container.querySelector('.btn-save').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'confirm-save-credential', credential }, (res) => {
        if (res?.success) {
          container.innerHTML = `<div class="title" style="color: #10b981; text-align: center;">✅ Saved to Vault!</div>`;
          setTimeout(() => host.remove(), 1500);
        } else {
          container.innerHTML = `<div class="title" style="color: #ef4444;">❌ Vault Locked.</div>`;
          setTimeout(() => host.remove(), 2000);
        }
      });
    });

    shadow.appendChild(style);
    shadow.appendChild(container);
    document.body.appendChild(host);
  }

  // ══════════════════════════════════
  //  VAULT UNLOCK PROMPT UI
  // ══════════════════════════════════

  function renderUnlockPrompt(anchorField) {
    if (activeDropdownHost) activeDropdownHost.remove();
    
    const host = document.createElement('deadbolt-unlock-prompt');
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host { position: absolute !important; z-index: 2147483647 !important; }
      .container {
        position: absolute; top: 8px; left: 0; width: 260px;
        background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px;
        box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1);
        font-family: 'Inter', -apple-system, sans-serif;
        padding: 12px; pointer-events: all;
        opacity: 0; transform: translateY(-5px); transition: all 0.2s ease;
      }
      .container.visible { opacity: 1; transform: translateY(0); }
      .title { font-size: 14px; font-weight: 600; color: #0f172a; margin-bottom: 8px; display: flex; align-items: center; gap: 6px; }
      .input-wrapper { display: flex; gap: 6px; }
      input {
        flex: 1; padding: 6px 10px; border: 1px solid #cbd5e1; border-radius: 6px;
        font-size: 13px; outline: none; transition: border-color 0.15s; width: 100%;
      }
      input:focus { border-color: #f97316; box-shadow: 0 0 0 2px rgba(249, 115, 22, 0.1); }
      button {
        background: #f97316; color: white; border: none; padding: 0 12px;
        border-radius: 6px; font-weight: 500; cursor: pointer; transition: opacity 0.2s;
      }
      button:hover { opacity: 0.9; }
      .error { color: #ef4444; font-size: 11px; margin-top: 6px; display: none; }
    `;

    const container = document.createElement('div');
    container.className = 'container';
    container.innerHTML = `
      <div class="title"><span>🔒</span> Vault Locked</div>
      <form class="input-wrapper">
        <input type="password" placeholder="Master Password" autocomplete="off" autofocus>
        <button type="submit">Unlock</button>
      </form>
      <div class="error">Incorrect master password.</div>
    `;

    const form = container.querySelector('form');
    const input = container.querySelector('input');
    const error = container.querySelector('.error');
    const btn = container.querySelector('button');

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const pw = input.value;
      if (!pw) return;

      btn.textContent = '...';
      btn.disabled = true;

      chrome.runtime.sendMessage({ action: 'unlock-vault', password: pw }, (res) => {
        if (res?.success) {
          container.innerHTML = `<div class="title" style="color: #10b981; justify-content: center; margin: 0;">🔓 Vault Unlocked!</div>`;
          setTimeout(() => {
            host.remove();
            activeDropdownHost = null;
            // Retry the original autofill request
            if (lastClickedField) {
              chrome.runtime.sendMessage({
                action: 'request-autofill',
                url: window.location.href,
                hostname: window.location.hostname,
                formType: lastClickedFormType
              });
            }
          }, 1000);
        } else {
          btn.textContent = 'Unlock';
          btn.disabled = false;
          error.style.display = 'block';
          input.value = '';
          input.focus();
        }
      });
    });

    shadow.appendChild(style);
    shadow.appendChild(container);

    const parent = anchorField.parentElement;
    if (parent) {
      anchorField.insertAdjacentElement('afterend', host);
      host.style.position = 'absolute';
      const anchorRect = anchorField.getBoundingClientRect();
      container.style.top = (anchorField.offsetTop + anchorRect.height + 4) + 'px';
      container.style.left = anchorField.offsetLeft + 'px';

      requestAnimationFrame(() => {
        container.classList.add('visible');
        input.focus();
      });
      activeDropdownHost = host;
    }
  }

  // ══════════════════════════════════
  //  AUTO-FILL ENGINE
  //  Fills detected fields using native value setters
  //  (Framework-compatible: React, Vue, Angular, etc.)
  // ══════════════════════════════════

  function performAutofill(username, password) {
    const forms = detectForms();
    let filled = false;

    // Prefer LOGIN forms for auto-fill
    const loginForms = forms.filter(f => f.formType === FormType.LOGIN);
    const targetForms = loginForms.length > 0 ? loginForms : forms;

    for (const { fields } of targetForms) {
      const usernameField = fields.find(f =>
        f.fieldType === FieldType.EMAIL ||
        f.fieldType === FieldType.USERNAME
      );
      const passwordField = fields.find(f =>
        f.fieldType === FieldType.PASSWORD_CURRENT
      );

      if (username && usernameField) {
        fillField(usernameField.element, username);
        flashField(usernameField.element);
        filled = true;
      }

      if (password && passwordField) {
        fillField(passwordField.element, password);
        flashField(passwordField.element);
        filled = true;
      }

      if (filled) break;
    }

    // Fallback: if no classified form found, try raw field detection
    if (!filled) {
      const passwordFields = Array.from(document.querySelectorAll('input[type="password"]')).filter(f => isVisible(f));
      if (passwordFields.length > 0 && password) {
        fillField(passwordFields[0], password);
        flashField(passwordFields[0]);
        filled = true;

        // Find adjacent username field
        if (username) {
          const usernameInput = findAdjacentUsernameField(passwordFields[0]);
          if (usernameInput) {
            fillField(usernameInput, username);
            flashField(usernameInput);
          }
        }
      }
    }

    return filled;
  }

  function findAdjacentUsernameField(passwordField) {
    const form = passwordField.closest('form');
    const scope = form || passwordField.parentElement?.parentElement?.parentElement || document;
    const inputs = Array.from(scope.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
    )).filter(isVisible);

    // Find the input that appears just before the password field in DOM order
    for (let i = inputs.length - 1; i >= 0; i--) {
      const input = inputs[i];
      if (passwordField.compareDocumentPosition(input) & Node.DOCUMENT_POSITION_PRECEDING) {
        return input;
      }
    }

    return inputs[0] || null;
  }

  // Native input value setter — compatible with React, Vue, Angular
  // (Mirrors Proton Pass's approach)
  function fillField(field, value) {
    // Focus the field first
    field.focus();

    // Use native descriptor to bypass framework getters/setters
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }

    // Dispatch full event sequence to trigger framework change detection
    field.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
    field.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
    field.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, key: 'Unidentified' }));
    field.dispatchEvent(new KeyboardEvent('keypress', { bubbles: true, key: 'Unidentified' }));
    field.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: 'Unidentified' }));
  }

  function flashField(field) {
    const originalOutline = field.style.outline;
    const originalTransition = field.style.transition;
    const originalBoxShadow = field.style.boxShadow;

    field.style.transition = 'all 0.3s ease';
    field.style.outline = '2px solid #58a6ff';
    field.style.boxShadow = '0 0 0 3px rgba(88, 166, 255, 0.2)';

    setTimeout(() => {
      field.style.outline = originalOutline;
      field.style.boxShadow = originalBoxShadow;
      setTimeout(() => { field.style.transition = originalTransition; }, 300);
    }, 1500);
  }

  // ══════════════════════════════════
  //  PHISHING BLOCKER UI
  // ══════════════════════════════════

  function renderPhishingBlocker(suspiciousDomain, safeDomain) {
    const host = document.createElement('div');
    document.documentElement.appendChild(host);
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host {
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        z-index: 2147483647 !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        background: rgba(220, 38, 38, 0.95) !important;
        backdrop-filter: blur(10px) !important;
        font-family: 'Inter', system-ui, -apple-system, sans-serif !important;
      }
      .phishing-card {
        background: #ffffff;
        padding: 48px;
        border-radius: 24px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        max-width: 600px;
        text-align: center;
        color: #0f172a;
      }
      .icon-wrap {
        width: 80px; height: 80px;
        background: #fee2e2; color: #dc2626;
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        margin: 0 auto 24px;
      }
      .icon-wrap svg { width: 40px; height: 40px; }
      h1 { margin: 0 0 16px; font-size: 32px; font-weight: 800; color: #dc2626; }
      p { margin: 0 0 24px; font-size: 18px; line-height: 1.5; color: #334155; }
      strong { color: #0f172a; font-weight: 700; background: #f1f5f9; padding: 2px 6px; border-radius: 4px; }
      .btn-leave {
        background: #dc2626; color: white;
        border: none; padding: 16px 32px; border-radius: 12px;
        font-size: 18px; font-weight: 700; cursor: pointer;
        transition: transform 0.2s; width: 100%; margin-bottom: 16px;
      }
      .btn-leave:hover { background: #b91c1c; transform: scale(1.02); }
      .btn-bypass {
        background: none; border: none; color: #94a3b8;
        font-size: 14px; cursor: pointer; text-decoration: underline;
      }
      .btn-bypass:hover { color: #64748b; }
    `;

    const container = document.createElement('div');
    container.className = 'phishing-card';
    container.innerHTML = `
      <div class="icon-wrap">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <h1>Security Alert</h1>
      <p>This website (<strong>${suspiciousDomain}</strong>) looks suspiciously similar to a site saved in your vault (<strong>${safeDomain}</strong>).</p>
      <p>This is highly likely a phishing attempt to steal your password.</p>
      <button class="btn-leave">Get me out of here</button>
      <button class="btn-bypass">I know the risks, let me in (False Positive)</button>
    `;

    shadow.appendChild(style);
    shadow.appendChild(container);

    shadow.querySelector('.btn-leave').addEventListener('click', () => {
      window.history.back();
      setTimeout(() => { window.location.href = 'about:blank'; }, 100);
    });

    shadow.querySelector('.btn-bypass').addEventListener('click', () => {
      host.remove();
    });
  }

  // ══════════════════════════════════
  //  MESSAGE HANDLING
  //  Listens for commands from popup & background
  // ══════════════════════════════════

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    switch (message.action) {
      case 'autofill': {
        const success = performAutofill(message.username, message.password);
        sendResponse({ success });
        break;
      }

      case 'show-dropdown': {
        if (lastClickedField) {
          renderDropdown(message.credentials, lastClickedField);
        }
        break;
      }

      case 'show-save-banner': {
        renderSavePrompt(message.credential);
        break;
      }

      case 'prompt-unlock': {
        if (lastClickedField) {
          renderUnlockPrompt(lastClickedField);
        }
        break;
      }

      case 'detect-forms': {
        // Return detected form info for the popup to show matching entries
        const forms = detectForms();
        const formInfo = forms.map(f => ({
          formType: f.formType,
          fieldCount: f.fields.length,
          fieldTypes: f.fields.map(ff => ff.fieldType),
          hasPassword: f.fields.some(ff => ff.fieldType === FieldType.PASSWORD_CURRENT || ff.fieldType === FieldType.PASSWORD_NEW),
          hasUsername: f.fields.some(ff => ff.fieldType === FieldType.EMAIL || ff.fieldType === FieldType.USERNAME)
        }));
        sendResponse({ forms: formInfo, url: window.location.href, hostname: window.location.hostname });
        break;
      }

      case 'highlight-fields': {
        // Debug: highlight all detected fields
        const forms = detectForms();
        forms.forEach(({ fields }) => {
          fields.forEach(({ element, fieldType }) => {
            element.style.outline = fieldType.includes('password') ? '2px solid #f85149' : '2px solid #58a6ff';
          });
        });
        sendResponse({ ok: true });
        break;
      }

      case 'phishing-alert': {
        renderPhishingBlocker(message.suspiciousDomain, message.safeDomain);
        break;
      }
    }
    return true;
  });

  // ══════════════════════════════════
  //  MUTATION OBSERVER
  //  Watches for dynamically added forms (SPA support)
  //  (Mirrors Proton Pass orchestrator pattern)
  // ══════════════════════════════════

  let scanTimer = null;
  const SCAN_DEBOUNCE = 800; // ms

  function scheduleScan() {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(() => {
      const forms = detectForms();
      injectIcons(forms);
      // Notify background about detected login forms
      if (forms.some(f => f.formType === FormType.LOGIN)) {
        try {
          chrome.runtime.sendMessage({
            action: 'login-form-detected',
            hostname: window.location.hostname,
            url: window.location.href
          });
        } catch { /* Extension context invalidated */ }
      }
    }, SCAN_DEBOUNCE);
  }

  // Initial scan
  function initialScan() {
    const forms = detectForms();
    injectIcons(forms);

    // Notify background about detected login forms
    if (forms.some(f => f.formType === FormType.LOGIN)) {
      try {
        chrome.runtime.sendMessage({
          action: 'login-form-detected',
          hostname: window.location.hostname,
          url: window.location.href
        });
      } catch { /* Extension context invalidated */ }
    }
  }

  // Run initial scan when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(initialScan, 300));
  } else {
    setTimeout(initialScan, 300);
  }

  // Observe DOM mutations for SPA navigation and dynamically loaded forms
  const observer = new MutationObserver((mutations) => {
    // Only rescan if nodes were added/removed (not just attribute changes)
    const hasRelevantChange = mutations.some(m =>
      m.type === 'childList' && (m.addedNodes.length > 0 || m.removedNodes.length > 0)
    );
    if (hasRelevantChange) {
      scheduleScan();
    }
  });

  observer.observe(document.documentElement || document.body, {
    childList: true,
    subtree: true
  });

  // Also rescan on URL change (SPA navigation via pushState/replaceState)
  let lastUrl = location.href;
  const urlObserver = new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      scheduleScan();
    }
  });
  urlObserver.observe(document.querySelector('title') || document.head, {
    childList: true,
    subtree: true,
    characterData: true
  });

  // Listen for popstate (browser back/forward)
  window.addEventListener('popstate', scheduleScan);

})();
