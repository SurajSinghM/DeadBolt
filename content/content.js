

(() => {
  'use strict';

  if (window.__deadboltInjected) return;
  window.__deadboltInjected = true;

  let sessionActionToken = null;

  ['keydown', 'keypress', 'keyup', 'input', 'beforeinput', 'compositionstart', 'compositionupdate', 'compositionend'].forEach(evt => {
    window.addEventListener(evt, (e) => {
      if (e.composed && e.composedPath) {
        const path = e.composedPath();
        if (path.some(node => node.nodeName && node.nodeName.toLowerCase() === 'deadbolt-unlock-prompt')) {
          e.stopImmediatePropagation();
          e.stopPropagation();
        }
      }
    }, true);
  });

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

  const RE = {

    PASSWORD: /p(?:hrasesecrete|ass(?:(?:phras|cod)e|wor[dt]))|(?:c(?:havesecret|lavesecret|ontrasen)|deseguranc)a|(?:(?:zugangs|secret)cod|clesecret)e|wachtwoord|codesecret|motdepasse|geheimnis|secret|heslo|senha|key/i,

    USERNAME: /gebruikersnaam|(?:identifi(?:cado|e)|benutze)r|identi(?:fiant|ty)|u(?:tilisateur|s(?:ername|uario))|(?:screen|nick)name|nutzername|(?:anmeld|handl)e|pseudo/i,

    EMAIL: /co(?:urriel|rrei?o)|email/i,

    CONFIRM: /digitarnovamente|v(?:olveraescribi|erifi(?:ca|e))r|saisiranouveau|(?:erneuteingeb|wiederhol|bestatig)en|verif(?:izieren|y)|re(?:pe(?:t[ei]r|at)|type)|confirm|again/i,

    SECOND: /\b\S*(?:snd|bis|2)\b/i,

    MFA: /(?:doublefacteu|(?:doblefac|zweifak|twofac)to)r|verifica(?:c(?:ion|ao)|tion)|multifa(?:ct(?:eu|o)|k?to)r|(?:securitycod|doubleetap|authcod)e|zweischritte|dois(?:fatore|passo)s|doblepaso|2(?:s(?:chritte|tep)|(?:etap[ae]|paso)s|fa)|twostep/i,
    OTP: /(?:authentication|approvals|email|login)code|phoneverification|challenge|t(?:wo(?:fa(?:ctor)?|step)|facode)|2fa|\b([mt]fa)\b/i,
    OTP_TOKEN: /totp(?:pin)?|o(?:netime|t[cp])|1time/i,

    RECOVERY: /schwierigkeit|(?:difficult|troubl|oubli|hilf)e|i(?:nciden(?:cia|t)|ssue)|vergessen|esquecido|olvidado|needhelp|questao|problem|forgot|ayuda/i,

    STEP: /p(?:rogres(?:s(?:ion|o)|o)|aso)|fortschritt|progress|s(?:chritt|t(?:age|ep))|etap[ae]|phase/i,

    NEWSLETTER: /newsletter|b(?:ul|o)letin|mailing/i,

    REGISTER: /regist(?:ration|er|rieren)|anmeld(?:en|ung)|s(?:ubscri(?:be|ption)|ign.?up|crivers|inscrire)|inscription|create.?account|new.?account|open.?account|join|enroll/i,

    LOGIN: /log.?(?:in|on)|sign.?in|anmelden|einloggen|iniciar.?ses|connexion|enter|authenticate|auth/i,

    CREDIT_CARD: /(?:payments?|new)card|c(?:ar(?:tecredit|d)|red(?:it(?:debit|card)|card))|stripe|vads/i,

    SEARCH: /search|busca|cherch|suche|zoek|szuk|recherch/i
  };

  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();

    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;

    if (rect.width === 0 && rect.height === 0 && style.overflow === 'hidden') return false;

    if (rect.x + rect.width < 0 || rect.y + rect.height < 0) return false;

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

    if (field.id) {
      const label = field.ownerDocument.querySelector(`label[for="${field.id}"]`);
      if (label) parts.push(label.textContent || '');
    }

    const wrappingLabel = field.closest('label');
    if (wrappingLabel) parts.push(wrappingLabel.textContent || '');

    return parts.map(s => s.trim().toLowerCase().replace(/\s+/g, '')).join('|');
  }

  function classifyField(field) {
    const type = (field.type || '').toLowerCase();
    const fingerprint = getFieldFingerprint(field);
    const autocomplete = (field.autocomplete || '').toLowerCase();

    if (type === 'password') {

      if (autocomplete === 'new-password' || RE.CONFIRM.test(fingerprint) || RE.SECOND.test(fingerprint)) {
        return FieldType.PASSWORD_NEW;
      }
      return FieldType.PASSWORD_CURRENT;
    }

    if (type === 'search' || RE.SEARCH.test(fingerprint)) return null;

    if (RE.CREDIT_CARD.test(fingerprint)) return null;

    if (RE.NEWSLETTER.test(fingerprint)) return null;

    if (['file', 'button', 'submit', 'reset', 'checkbox', 'radio', 'image', 'hidden', 'range', 'color', 'date', 'datetime-local', 'month', 'week', 'time'].includes(type)) {
      return null;
    }

    if (autocomplete === 'username' || autocomplete === 'email') return FieldType.EMAIL;
    if (autocomplete === 'one-time-code') return FieldType.OTP;

    if (RE.OTP.test(fingerprint) || RE.OTP_TOKEN.test(fingerprint) || RE.MFA.test(fingerprint)) {
      return FieldType.OTP;
    }

    if (type === 'email' || RE.EMAIL.test(fingerprint)) return FieldType.EMAIL;

    if (RE.USERNAME.test(fingerprint)) return FieldType.USERNAME;

    if (type === 'tel') {
      if (RE.OTP.test(fingerprint) || RE.MFA.test(fingerprint)) return FieldType.OTP;
      return null;
    }

    if (type === 'text' || type === '') {
      return FieldType.USERNAME;
    }

    return null;
  }

  function classifyForm(form, fields) {
    const passwordFields = fields.filter(f => f.fieldType === FieldType.PASSWORD_CURRENT || f.fieldType === FieldType.PASSWORD_NEW);
    const newPasswords = fields.filter(f => f.fieldType === FieldType.PASSWORD_NEW);
    const currentPasswords = fields.filter(f => f.fieldType === FieldType.PASSWORD_CURRENT);
    const usernameFields = fields.filter(f => f.fieldType === FieldType.EMAIL || f.fieldType === FieldType.USERNAME);
    const otpFields = fields.filter(f => f.fieldType === FieldType.OTP);

    if (passwordFields.length === 0 && usernameFields.length === 0 && otpFields.length === 0) {
      return FormType.NOOP;
    }

    const pageText = (document.title + ' ' + window.location.href).toLowerCase();
    const formFingerprint = form ? getFormFingerprint(form) : '';

    if (passwordFields.length === 0 && usernameFields.length > 0 && otpFields.length === 0) {
      if (RE.RECOVERY.test(pageText) || RE.RECOVERY.test(formFingerprint)) {
        return FormType.RECOVERY;
      }
    }

    if (otpFields.length > 0 && passwordFields.length === 0) {
      return FormType.NOOP; // Not a form we fill with username/password
    }

    if (newPasswords.length > 0 || passwordFields.length >= 2 ||
        RE.REGISTER.test(pageText) || RE.REGISTER.test(formFingerprint)) {
      return FormType.REGISTER;
    }

    if (currentPasswords.length >= 1 && passwordFields.length >= 2) {
      return FormType.PASSWORD_CHANGE;
    }

    if (passwordFields.length >= 1) {
      return FormType.LOGIN;
    }

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

  function detectForms() {
    const detectedForms = [];

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

    const groups = [];
    const used = new Set();

    fields.forEach(field => {
      if (used.has(field)) return;

      const group = [field];
      used.add(field);

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

      if (['SECTION', 'MAIN', 'ARTICLE', 'BODY'].includes(tag)) return current;

      const role = current.getAttribute('role');
      if (role === 'form' || role === 'dialog' || role === 'main') return current;

      const cls = (current.className || '').toLowerCase();
      if (/form|login|auth|sign|modal|card|panel|container/i.test(cls)) return current;
      current = current.parentElement;
      depth++;
    }
    return current || el.parentElement;
  }

  const injectedFields = new WeakSet();
  let activeDropdownHost = null;
  let lastClickedField = null;
  let lastClickedFormType = null;

  let credentialsExistForSite = false;
  let credentialsCheckComplete = false;

  try {
    chrome.runtime.sendMessage({ action: 'check-credentials-exist', hostname: window.location.hostname }, (res) => {
      credentialsCheckComplete = true;
      if (res && res.exists) {
        credentialsExistForSite = true;
        scheduleScan();
      }
    });
  } catch (e) {
    credentialsCheckComplete = true;
  }

  function injectIcons(detectedForms) {
    detectedForms.forEach(({ formType, fields }) => {
      if (![FormType.LOGIN, FormType.REGISTER, FormType.PASSWORD_CHANGE].includes(formType)) return;

      fields.forEach(({ element: field, fieldType }) => {
        if (fieldType === FieldType.OTP) return;

        if (credentialsCheckComplete && credentialsExistForSite) {
          if (injectedFields.has(field)) return;
          injectFieldIcon(field, formType);
          injectedFields.add(field);
        }
      });
      
      trackFieldInteractions(fields);
    });
  }

  const trackedFields = new Map();

  const disappearanceObserver = new MutationObserver(() => {
    if (trackedFields.size === 0) return;
    for (const [pwEl, state] of trackedFields.entries()) {
      if (state.password && state.username) { // Only track if they typed something
        if (!document.body.contains(pwEl) || !isVisible(pwEl)) {
          triggerSave(pwEl, state);
          trackedFields.delete(pwEl); // Stop tracking once saved
        }
      }
    }
  });

  disappearanceObserver.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class']
  });

  function trackFieldInteractions(fields) {
    const pwFields = fields.filter(f => f.fieldType === FieldType.PASSWORD_CURRENT || f.fieldType === FieldType.PASSWORD_NEW);
    const userFields = fields.filter(f => f.fieldType === FieldType.EMAIL || f.fieldType === FieldType.USERNAME);
    if (pwFields.length === 0) return;

    const pwEl = pwFields[0].element;
    const userEl = userFields.length > 0 ? userFields[0].element : null;

    if (pwEl.hasAttribute('data-deadbolt-tracked')) return;
    pwEl.setAttribute('data-deadbolt-tracked', 'true');

    const state = { username: '', password: '', isSubmitted: false };
    
    const updateState = () => {
      state.password = pwEl.value;
      if (userEl) state.username = userEl.value;
    };

    pwEl.addEventListener('input', updateState);
    if (userEl) userEl.addEventListener('input', updateState);

    trackedFields.set(pwEl, state);

    const form = pwEl.closest('form');
    if (form && !form.hasAttribute('data-deadbolt-listener')) {
      form.setAttribute('data-deadbolt-listener', 'true');
      form.addEventListener('submit', () => triggerSave(pwEl, state));
    }

    const container = findFormLikeContainer(pwEl);
    if (container && !container.hasAttribute('data-deadbolt-btn-listener')) {
      container.setAttribute('data-deadbolt-btn-listener', 'true');
      container.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        const btn = e.target.closest('button, input[type="submit"], input[type="button"], [role="button"]');
        if (btn && state.password) {

          setTimeout(() => checkDisappearance(pwEl, state), 100);
        }
      });
    }

    const onEnter = (e) => {
      if (e.key === 'Enter' && state.password) {
        setTimeout(() => checkDisappearance(pwEl, state), 100);
      }
    };
    pwEl.addEventListener('keydown', onEnter);
    if (userEl) userEl.addEventListener('keydown', onEnter);
  }

  function checkDisappearance(pwEl, state) {
    if (state.isSubmitted || !state.password) return;

    if (!document.body.contains(pwEl) || !isVisible(pwEl)) {
      triggerSave(pwEl, state);
    }
  }

  function triggerSave(pwEl, state) {
    if (state.isSubmitted || !state.password) return;
    state.isSubmitted = true;
    
    chrome.runtime.sendMessage({
      action: 'save-captured-credential',
      token: sessionActionToken,
      credential: {
        url: window.location.href,
        hostname: window.location.hostname,
        username: state.username,
        password: state.password
      }
    });
    
    setTimeout(() => {
      chrome.runtime.sendMessage({ action: 'check-pending-saves', token: sessionActionToken }, (res) => {
        if (res?.credential) renderSavePrompt(res.credential);
      });
    }, 1500);
  }

  function injectFieldIcon(field, formType) {

    const host = document.createElement('deadbolt-icon');
    const shadow = host.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
      :host {
        
      }
      button {
        pointer-events: all;
        position: absolute;
        cursor: pointer;
        background: #111118;
        border: 1px solid #2a2a35;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
        opacity: 0;
        transform: translateY(-50%) scale(0.5);
        transition: opacity 0.2s ease, transform 0.2s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
        padding: 4px;
        box-sizing: border-box;
      }
      button.visible {
        opacity: 0.95;
        transform: translateY(-50%) scale(1);
      }
      button:hover {
        opacity: 1;
        transform: translateY(-50%) scale(1.1);
        background: #1f1f28;
      }
      button img {
        width: 100%;
        height: 100%;
        object-fit: contain;
        pointer-events: none;
      }
    `;

    const button = document.createElement('button');
    button.title = 'Fill with DeadBolt';
    const iconUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAELUlEQVR4AexWTYhcRRCu6u73ZnYHV/YgxOySdSVkhfUQL+vmtoILERdyUBYPioLgQTxowEsggoh4MwjixYO/ILhBojEBs140oAmCIh6MIbLKxkv0ELPs7Jv35nX59Zt5M+9N+s2qJOSyzavuqurqqq+ra4pRdIvHDoCdDAzNwObm5p2tVuseEZkRiUCyD/w+iaIZp3ckW1t3ra+vj/zfWq4EEMfxm/V6/Y8gCH4WsRdEQpD8IgIKwwtO70hqtbWJiYm/0yT5IUlaL2F/138B4wXQbDYnjVHPMhN3nLlFOqx/Dljr/VoHL1trf02S5AiAGL9pWavKYkfSWt8uohAVX0eFuc/DOeTyl+uYeRTnX03T9DR0t5Wtrpe8AELYMQ+7sWyStadE0mMI9AZu/QWObIF6n1JqEXufAYRz19MPMl4AMcUkiI/DJXvI7TRNXrt2bWNSGbOElB9GHTxvjDmIgt2DgMdwIAVlH0AsxO34lUyomLwAMltmYuaMdROCt0CHgqB2ZHx8/KrTFWlsbOwvgDmM938Mdu18L9DmhSiK9uby4FoJgAkp6FrDIeF2L+Kmp7uqbNnY2Lg3iaJF7AeZAlOtVjtubfsodMii88EBauI5bHm/SgDuCfon5BJu91ZfJkIPWG40Gj/qMDiTpumJ4t7Fi5deB4DLeQK1VoeK+0XeCyAMQ2Hinp218jEzpz0FGK21c4rzTIr54NraWp26Y3Z2Nhaxx6nng6eQrTvIM+Dgei2aUC+6S6JN7E+DVu12+yMRSUCEylyZnp6OijbIYPEM42kmi/s57wUQUig98M5SU8stRUKX/FysPc8wtNYeLe45HsDKZxLyNiYvAOcgJwaD9O/BUvoQIGDF9wmK1TDPlTYh4Cc4BRtwhGIkClR6JRMGJjUg90Xps3D2cF/qcGjX+4m4AXBEmg/QwGCmJWbuauXqysmTl7tCaakGgJvllvDzIAKWghhDu5nlnE3T82Sp1O3QCx5QSs/3MyCry8vLae6vuHoBxJlFjp6IkWsU0fvFSq7VGp8qZQ6YIJg3YfgMdQc64m6l1DsQGQMLEQr27YzxTF4AHTu8Lkq5wxPB2d7R0dGz+IUg9eQd2JtDcZ6F7VRuYG26Ct1qLg+uQwCQC0rFAcczRpvvcKMVNKLHEfD+uNmcx/pku52cQKf8BjZ352dE7BWtzdO57FurAXD/CUoHmQxS/Cg64wcIeM7U699ifVeprDHp3BbB/4yi1kPMvJ7rfKsXAH7XTUH6HfkObadD2r+O42QOrfr77Wy9AEZGRn4XsWeAfrvzvX3BnwME/grgH9HaLMDHb/QvhhcAzgmcLNk4XoLDp4ZSkjwRx/Eiqn+XMcGCMeYTAC90EXgb8lUBcAWY4H1PweF7Q6lW+xBV/qX7PzAkTuVWJYDKEzd4YwfATc/Adi/2DwAAAP//Se/T8wAAAAZJREFUAwAM0+ZQEDRaIQAAAABJRU5ErkJggg==';
    button.innerHTML = `<img src="${iconUrl}" alt="DeadBolt">`;

    shadow.appendChild(style);
    shadow.appendChild(button);

    host.style.position = 'absolute';
    host.style.top = '0';
    host.style.left = '0';
    host.style.width = '100%';
    host.style.height = '0';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'none';

    button.style.position = 'absolute';
    button.style.pointerEvents = 'all'; // allow clicking the button itself
    const size = 26;
    button.style.width = size + 'px';
    button.style.height = size + 'px';

    const positionIcon = () => {
      const rect = field.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0) return; // Hidden field

      const absoluteTop = rect.top + window.scrollY;
      const absoluteLeft = rect.left + window.scrollX;

      button.style.left = (absoluteLeft + rect.width - size - 10) + 'px';
      button.style.top = (absoluteTop + rect.height / 2) + 'px';

      const computedStyle = window.getComputedStyle(field);
      const computedPadding = parseInt(computedStyle.paddingRight || '0', 10);
      if (computedPadding < size + 16) {
        field.style.paddingRight = (size + 16) + 'px';
      }

      requestAnimationFrame(() => button.classList.add('visible'));
    };

    document.body.appendChild(host);
    positionIcon();

    const resizeObserver = new ResizeObserver(positionIcon);
    resizeObserver.observe(field);
    window.addEventListener('resize', positionIcon, { passive: true });

    window.addEventListener('scroll', positionIcon, { passive: true, capture: true });

    button.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      e.preventDefault();
      e.stopPropagation();

      lastClickedField = field;
      lastClickedFormType = formType;

      chrome.runtime.sendMessage({
        action: 'request-autofill',
        token: sessionActionToken,
        url: window.location.origin,
        hostname: window.location.hostname,
        formType: formType
      });
    });

    field.addEventListener('focus', () => button.classList.add('visible'));
    field.addEventListener('blur', () => {
      setTimeout(() => button.classList.remove('visible'), 200);
    });

    button.classList.remove('visible');
    const parentNode = field.parentElement;
    if (parentNode) {
      parentNode.addEventListener('mouseenter', () => button.classList.add('visible'));
      parentNode.addEventListener('mouseleave', () => {
        if (document.activeElement !== field) button.classList.remove('visible');
      });
    }
  }

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
        if (!e.isTrusted) return;
        e.preventDefault();
        e.stopPropagation();

        chrome.runtime.sendMessage({ action: 'get-credential', id: cred.id, token: sessionActionToken }, (response) => {
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
        if (!e.isTrusted) return;
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

    const parent = anchorField.parentElement;
    if (parent) {
      anchorField.insertAdjacentElement('afterend', host);

      host.style.position = 'absolute';
      
      const anchorRect = anchorField.getBoundingClientRect();

      container.style.top = (anchorField.offsetTop + anchorRect.height + 4) + 'px';
      container.style.left = anchorField.offsetLeft + 'px';

      requestAnimationFrame(() => container.classList.add('visible'));
      activeDropdownHost = host;
    }
  }

  document.addEventListener('click', (e) => {
    if (activeDropdownHost) {
      const path = e.composedPath();
      if (!path.includes(activeDropdownHost)) {
        activeDropdownHost.remove();
        activeDropdownHost = null;
      }
    }
  });

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
        background: #111118;
        border: 1px solid #1e1e28;
        border-radius: 12px;
        box-shadow: 0 12px 32px rgba(0,0,0,0.5), 0 4px 8px rgba(0,0,0,0.3);
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        padding: 16px;
        pointer-events: all;
        display: flex;
        flex-direction: column;
        gap: 12px;
        width: 300px;
        animation: slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      .title { font-weight: 600; color: #f1f5f9; font-size: 15px; display: flex; align-items: center; gap: 8px; }
      .desc { font-size: 13px; color: #94a3b8; margin: 0; }
      .buttons { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }
      button {
        padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; border: none; transition: all 0.15s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .btn-cancel { background: #1e1e28; color: #94a3b8; border: 1px solid #2a2a35; }
      .btn-cancel:hover { background: #2a2a35; color: #f1f5f9; }
      .btn-save { background: #f97316; color: #ffffff; }
      .btn-save:hover { background: #ea580c; transform: translateY(-1px); box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
      .btn-save:active { transform: translateY(0); box-shadow: none; }
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

    container.querySelector('.btn-cancel').addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      host.remove();
    });
    container.querySelector('.btn-save').addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      chrome.runtime.sendMessage({ action: 'confirm-save-credential', token: sessionActionToken, credential }, (res) => {
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

  function renderUnlockPrompt(anchorField) {
    if (activeDropdownHost) activeDropdownHost.remove();
    
    const host = document.createElement('iframe');
    host.src = chrome.runtime.getURL('unlock/unlock.html');
    host.style.cssText = `
      position: absolute !important;
      z-index: 2147483647 !important;
      border: none !important;
      background: transparent !important;
      width: 290px !important;
      height: 130px !important;
      border-radius: 12px !important;
      box-shadow: none !important;
    `;

    const parent = anchorField.parentElement;
    if (parent) {
      anchorField.insertAdjacentElement('afterend', host);
      const anchorRect = anchorField.getBoundingClientRect();
      host.style.top = (anchorField.offsetTop + anchorRect.height + 4) + 'px';
      activeDropdownHost = host;

      requestAnimationFrame(() => {
        host.focus();
      });
    }
  }

  window.addEventListener('message', (e) => {

    if (e.origin !== chrome.runtime.getURL('').replace(/\/$/, '')) return;

    if (e.data?.type === 'DEADBOLT_UNLOCKED') {
      if (activeDropdownHost) {
        activeDropdownHost.remove();
        activeDropdownHost = null;
      }

      if (lastClickedField) {
        chrome.runtime.sendMessage({
          action: 'request-autofill',
          token: sessionActionToken,
          url: window.location.origin,
          hostname: window.location.hostname,
          formType: lastClickedFormType
        });
      }
    } else if (e.data?.type === 'DEADBOLT_DISMISS_UNLOCK') {
      if (activeDropdownHost) {
        activeDropdownHost.remove();
        activeDropdownHost = null;
      }
    }
  });

  function performAutofill(username, password) {
    const forms = detectForms();
    let filled = false;

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

    if (!filled) {
      const passwordFields = Array.from(document.querySelectorAll('input[type="password"]')).filter(f => isVisible(f));
      if (passwordFields.length > 0 && password) {
        fillField(passwordFields[0], password);
        flashField(passwordFields[0]);
        filled = true;

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

    for (let i = inputs.length - 1; i >= 0; i--) {
      const input = inputs[i];
      if (passwordField.compareDocumentPosition(input) & Node.DOCUMENT_POSITION_PRECEDING) {
        return input;
      }
    }

    return inputs[0] || null;
  }

  function fillField(field, value) {

    field.focus();

    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeSetter) {
      nativeSetter.call(field, value);
    } else {
      field.value = value;
    }

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

        const forms = detectForms();
        const formInfo = forms.map(f => ({
          formType: f.formType,
          fieldCount: f.fields.length,
          fieldTypes: f.fields.map(ff => ff.fieldType),
          hasPassword: f.fields.some(ff => ff.fieldType === FieldType.PASSWORD_CURRENT || ff.fieldType === FieldType.PASSWORD_NEW),
          hasUsername: f.fields.some(ff => ff.fieldType === FieldType.EMAIL || ff.fieldType === FieldType.USERNAME)
        }));
        sendResponse({ forms: formInfo, url: window.location.origin, hostname: window.location.hostname });
        break;
      }

      case 'highlight-fields': {

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
  });

  let scanTimer = null;
  const SCAN_DEBOUNCE = 800; // ms

  function scheduleScan() {
    if (scanTimer) clearTimeout(scanTimer);
    scanTimer = setTimeout(() => {
      const forms = detectForms();
      injectIcons(forms);
      if (forms.some(f => f.formType === FormType.LOGIN)) {
        try {
          chrome.runtime.sendMessage({
            action: 'login-form-detected',
            hostname: window.location.hostname,
            url: window.location.origin
          }, (res) => {
            if (res && res.token) sessionActionToken = res.token;
          });
        } catch {  }
      }
    }, SCAN_DEBOUNCE);
  }

  function initialScan() {
    const forms = detectForms();
    injectIcons(forms);
    if (forms.some(f => f.formType === FormType.LOGIN)) {
      try {
        chrome.runtime.sendMessage({
          action: 'login-form-detected',
          hostname: window.location.hostname,
          url: window.location.origin
        }, (res) => {
          if (res && res.token) sessionActionToken = res.token;
        });
      } catch {  }
    }
  }

  function setupObservers() {
    const observer = new MutationObserver((mutations) => {
      const hasRelevantChange = mutations.some(m =>
        m.type === 'childList' && (m.addedNodes.length > 0 || m.removedNodes.length > 0)
      );
      if (hasRelevantChange) {
        scheduleScan();
      }
    });

    observer.observe(document, {
      childList: true,
      subtree: true
    });

    let lastUrl = location.href;
    const urlObserver = new MutationObserver(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        scheduleScan();
      }
    });
    
    urlObserver.observe(document, {
      childList: true,
      subtree: true,
      characterData: true
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(initialScan, 300);
      setupObservers();
    });
  } else {
    setTimeout(initialScan, 300);
    setupObservers();
  }

  window.addEventListener('popstate', scheduleScan);

})();
