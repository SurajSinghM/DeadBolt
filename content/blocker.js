(() => {
  const TRACKER_KEYWORDS = [
    'hotjar', 'hj', 'fullstory', 'fs.js', 'logrocket', 'lr-ingest', 
    'inspectlet', 'clarity', 'smartlook', 'luckyorange', 'mouseflow', 
    'sessionstack', 'dynatrace', 'ruxit', 'contentsquare', 'heap.js', 
    'pendo', 'userpilot', 'appcues', 'sentry', 'bugsnag', 'datadog', 
    'google-analytics', 'googleanalytics', 'analytics.js', 'gtag', 'gtm.js', 
    'tagmanager', 'facebook', 'fbevents', 'fbpx', 'pixel', 'mixpanel',
    'amplitude', 'segment.io', 'segment.js', 'crazyegg'
  ];

  function isTrackerOrSpyware(stack) {
    if (!stack) return false;
    const stackLower = stack.toLowerCase();
    
    for (const keyword of TRACKER_KEYWORDS) {
      if (stackLower.includes(keyword)) return true;
    }
    
    return false;
  }

  function isSensitiveInput(el) {
    const type = (el.type || '').toLowerCase();
    if (type === 'password') return true;
    if (type === 'email') return true;
    const nameOrId = (el.name || '') + '|' + (el.id || '') + '|' + (el.placeholder || '') + '|' + (el.autocomplete || '');
    return /password|passcode|passphrase|secret|email|username|login|usr/i.test(nameOrId);
  }

  // 1. Intercept addEventListener to prevent keylogging
  const originalAddEventListener = HTMLInputElement.prototype.addEventListener;
  HTMLInputElement.prototype.addEventListener = function(type, listener, options) {
    if (isSensitiveInput(this) && ['keydown', 'keypress', 'keyup', 'input', 'change', 'paste'].includes(type)) {
      const stack = new Error().stack || '';
      if (isTrackerOrSpyware(stack)) {
        return;
      }
    }
    return originalAddEventListener.call(this, type, listener, options);
  };

  // 2. Intercept value getter to prevent reading input contents
  const originalValueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (originalValueDescriptor) {
    Object.defineProperty(HTMLInputElement.prototype, 'value', {
      get: function() {
        if (isSensitiveInput(this)) {
          const stack = new Error().stack || '';
          if (isTrackerOrSpyware(stack)) {
            return '';
          }
        }
        return originalValueDescriptor.get.call(this);
      },
      set: function(val) {
        originalValueDescriptor.set.call(this, val);
      },
      configurable: true
    });
  }
})();
