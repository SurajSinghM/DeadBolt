<div align="center">
  <img src="FullSizeLogo.png" alt="DeadBolt Logo" width="300">
</div>

# DeadBolt — Password Manager

DeadBolt is a premium, highly secure password manager extension for Chrome/Edge. It is designed with advanced security architecture, offering robust AES-256-GCM encryption, seamless form autofill, and advanced protection mechanisms against DOM-based attacks and keystroke logging.

## Features

### Core Capabilities
* **Secure Encryption:** All credentials are encrypted locally using `AES-256-GCM` before they are ever stored in the browser's local storage. Your master password never leaves your device.
* **Intelligent Auto-Fill Engine:** Advanced, multilingual regex-based form classification detects login, registration, and recovery forms, similar to enterprise password managers.
* **Auto-Capture:** DeadBolt detects when you submit a new login or registration form and prompts you to save the credential seamlessly.
* **Folders & Tags Management:** Organize your vault effortlessly. Filter, categorize, and visually distinguish your credentials with custom tags and folders.
* **Email Alias Generation:** Integrated with the SimpleLogin API, allowing you to generate disposable email aliases on the fly to protect your real identity during registration.
* **Strong Password Generator:** Built-in cryptographic password generator with customizable length and character sets.

### Advanced Security Architecture
* **Cross-Origin Iframe Isolation:** The master password unlock prompt is injected as a cross-origin extension iframe (`chrome-extension://...`). This ensures that malicious web pages cannot use capturing event listeners to intercept your keystrokes.
* **Confused Deputy Protection (Tokens & Origin Checks):** The background service worker strictly validates the sender's origin. Sensitive actions from content scripts require a one-time cryptographic session token, preventing malicious pages from forging background requests.
* **Hardware-Verified Interactions (`isTrusted`):** All injected UI elements (icons, dropdowns, prompts) strictly enforce `event.isTrusted`, neutralizing any programmatic click exploits.
* **Keystroke Spyware & Replay Blocker:** A dedicated document-start blocker script disrupts common session replay tools (like LogRocket, Hotjar) and global keyloggers from observing sensitive input fields.
* **Idle Auto-Lock:** Automatically locks your vault after a specified period of inactivity to prevent unauthorized access if you step away.

## Installation (Developer Mode)

Since DeadBolt is currently in active development, you must load it as an "Unpacked Extension" in Chrome:

1. Clone or download this repository to your local machine.
2. Open Google Chrome and navigate to the Extensions page: `chrome://extensions/`.
3. Enable **Developer mode** using the toggle switch in the top right corner.
4. Click the **Load unpacked** button in the top left.
5. Select the `DeadBolt` repository directory (the folder containing the `manifest.json` file).
6. DeadBolt will appear in your extensions list. Pin it to your toolbar for easy access!

## Architecture Overview

The extension is modularly built following Manifest V3 standards:

* **Background Service Worker (`background.js`):** Acts as the secure orchestrator. It manages the encryption/decryption keys (in memory), validates all incoming messages based on origin allowlists and cryptographic tokens, and handles external API calls (e.g., SimpleLogin).
* **Content Scripts (`content.js` & `blocker.js`):** 
  * `blocker.js` runs at `document_start` to neutralize tracking and replay scripts.
  * `content.js` handles DOM mutation observing to detect forms (even in SPAs), injects the DeadBolt UI elements, and securely communicates with the background worker using session tokens.
* **Popup (`popup/`):** The primary user interface for managing the vault, viewing credentials, updating settings, and managing tags/folders.
* **Isolated Iframe (`unlock/`):** A secure, extension-origin surface for collecting the master password when the vault is locked during an autofill attempt.

##  Configuration

To use the Email Alias generation feature, you must provide a SimpleLogin API key:
1. Unlock the DeadBolt extension.
2. Navigate to the **Settings** tab.
3. Paste your SimpleLogin API Key into the designated field.
4. (Optional) Adjust your Auto-Lock timer and Privacy settings.
