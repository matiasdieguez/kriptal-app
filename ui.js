import {
  VAULT_KEY,
  REPLAY_KEY,
  VERSION,
  MAX_MESSAGE_BYTES,
  MAX_FILE_BYTES,
  b64,
  bytes,
  fromJson,
  random,
  escapeHtml,
  readRoute,
  storeRecord,
  storedRecord,
  isReplayed,
  markReplayed,
  validMessage,
  validContact
} from './common.js';
import {
  encryptBytes,
  decryptBytes,
  encryptVault,
  decryptVault,
  sharedEcdh,
  hybridKey,
  signPayload,
  verifyPayload,
  encapsulate,
  decapsulate,
  newIdentity,
  publicFingerprint
} from './crypto.js';
import { languages, languageTag, translateAttribute, translateText } from './translations.js';

export function initUI({ app, toast }) {
  const textEncoder = new TextEncoder();
  let session = null;
  let theme = localStorage.getItem('kriptal-theme') === 'light' ? 'light' : 'dark';
  let view = 'compose';
  let routeMessage = readRoute('m');
  let routeKey = readRoute('k');
  let pendingLinkOpened = false;
  const pendingLaunchFiles = [];
  let processingLaunchFiles = false;
  const originalText = new WeakMap();
  const originalAttributes = new WeakMap();
  const languageSelect = document.querySelector('#language-select');
  let language = languages.some((item) => item.code === localStorage.getItem('kriptal-language'))
    ? localStorage.getItem('kriptal-language')
    : 'en';
  languageSelect.value = language;

  function localizeElement(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    let node;
    while ((node = walker.nextNode())) {
      if (!originalText.has(node)) originalText.set(node, node.nodeValue);
      const source = originalText.get(node);
      const trimmed = source.trim();
      if (!trimmed) continue;
      const translated = translateText(trimmed, language);
      const localized = translated === trimmed ? source : source.replace(trimmed, translated);
      if (node.nodeValue !== localized) node.nodeValue = localized;
    }
    root.querySelectorAll?.('[placeholder], [aria-label], [title]').forEach((element) => {
      if (!originalAttributes.has(element)) originalAttributes.set(element, {});
      const sources = originalAttributes.get(element);
      for (const attribute of ['placeholder', 'aria-label', 'title']) {
        const value = element.getAttribute(attribute);
        if (value) {
          if (!(attribute in sources)) sources[attribute] = value;
          element.setAttribute(attribute, translateAttribute(sources[attribute], language));
        }
      }
    });
  }

  function applyLanguage() {
    document.documentElement.lang = languageTag(language);
    languageSelect.value = language;
    localizeElement(document.body);
    const infoPage = new URLSearchParams(location.search).get('page');
    const infoTitle =
      infoPage === 'technical-details'
        ? 'Security & technical details'
        : infoPage === 'how-it-works'
          ? 'How Kriptal works'
          : null;
    document.title = infoTitle
      ? `${translateText(infoTitle, language)} | Kriptal`
      : translateText('Kriptal | Private, local-first encrypted messaging', language);
  }

  languageSelect.addEventListener('change', () => {
    language = languageSelect.value;
    localStorage.setItem('kriptal-language', language);
    applyLanguage();
  });

  const localizationObserver = new MutationObserver((records) => {
    for (const record of records) {
      if (record.target.nodeType === Node.ELEMENT_NODE && app.contains(record.target))
        localizeElement(record.target);
      else if (record.target.parentElement && app.contains(record.target.parentElement))
        localizeElement(record.target.parentElement);
      for (const added of record.addedNodes) {
        if (added.nodeType === Node.ELEMENT_NODE && app.contains(added))
          localizeElement(added);
      }
    }
  });
  localizationObserver.observe(app, { childList: true, subtree: true, characterData: true });

  function toastMessage(message) {
    toast.textContent = translateText(message, language);
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2600);
  }

  if (window.launchQueue?.setConsumer) {
    window.launchQueue.setConsumer((launchParams) => {
      pendingLaunchFiles.push(...launchParams.files);
      processLaunchFiles();
    });
  }

  function renderSetup() {
    app.classList.add('setup-screen');
    document.documentElement.lang = languageTag(language);
    const infoPage = new URLSearchParams(location.search).get('page');
    if (
      infoPage === 'how-it-works' ||
      infoPage === 'technical-details'
    ) {
      renderInfoPage(infoPage);
      return;
    }
    document.title = translateText('Kriptal | Private, local-first encrypted messaging', language);
    document.querySelector('meta[name="description"]').content =
      'Create a local identity, encrypt private messages for your contacts, and share them as files. Kriptal is a free, offline-first encrypted messaging PWA with no server inbox.';
    const hasAccount = Boolean(storedRecord());
    app.innerHTML = `<div class="setup-layout"><section class="setup-intro"><div class="eyebrow">Privacy is a Human Right</div><h1>Your messages, secured</h1><p class="lede">Kriptal is a private, local-first encrypted messaging app. Encrypt messages for a contact and share them as files—without a server, inbox, or account.</p><div class="info-links"><a class="info-link" href="?page=how-it-works">How Kriptal works <span aria-hidden="true">→</span></a><a class="info-link" href="?page=technical-details">Security & technical details <span aria-hidden="true">→</span></a><a class="info-link" href="./legal.html">Legal & disclaimer <span aria-hidden="true">→</span></a><a class="info-link" href="https://github.com/matiasdieguez/kriptal-app" target="_blank" rel="noopener noreferrer">GitHub repository <span aria-hidden="true">↗</span></a></div></section><section class="panel auth-panel"><div class="panel-head"><div><div class="section-label">${hasAccount ? 'Welcome back' : 'Create your identity'}</div><h2>${hasAccount ? 'Unlock your vault' : 'Set up your local vault'}</h2></div></div><div class="notice">Your vault is encrypted on this device. Messages use hybrid ML-KEM-768 + P-256 encryption and ML-DSA-65 sender authentication. Your password cannot be recovered.</div><form id="auth-form"><div class="form-grid">${!hasAccount ? '<div><label for="username">Your username</label><input id="username" name="username" required minlength="2" maxlength="32" placeholder="e.g. maren" autocomplete="username"></div>' : ''}<div class="${hasAccount ? 'full' : ''}"><label for="password">${hasAccount ? 'Vault password' : 'Choose a strong password'}</label><input id="password" name="password" type="password" required minlength="10" autocomplete="${hasAccount ? 'current-password' : 'new-password'}" placeholder="10 characters minimum"></div></div><div class="actions"><button type="submit">${hasAccount ? 'Unlock Kriptal' : 'Generate my identity'}</button>${hasAccount ? '<button type="button" class="danger" id="reset-account">Erase local vault</button>' : ''}</div></form></section></div>`;
    localizeElement(app);
    document.querySelector('#auth-form').addEventListener('submit', hasAccount ? unlock : setup);
    document.querySelector('#reset-account')?.addEventListener('click', () => {
      if (confirm('Erase your local identity and contacts? This cannot be undone.')) {
        localStorage.removeItem(VAULT_KEY);
        localStorage.removeItem(REPLAY_KEY);
        location.hash = '';
        renderSetup();
      }
    });
  }

  function renderInfoPage(page) {
    const technical = page === 'technical-details';
    const title = technical ? 'Security & technical details' : 'How Kriptal works';
    document.title = `${translateText(title, language)} | Kriptal`;
    document.querySelector('meta[name="description"]').content = technical
      ? 'Technical overview of Kriptal security: encrypted local vault, hybrid P-256 and ML-KEM-768 message encryption, ML-DSA-65 signatures, key handling, and limitations.'
      : 'Learn how Kriptal lets you create a local identity, exchange public keys, encrypt a message for a contact, and share it without a messaging server.';
    const content = technical
      ? `<h1>Security and technical details</h1><p class="lede">Kriptal encrypts messages on your device. There is no server inbox or message relay.</p><h2>Local vault</h2><p>Your identity and contacts are stored in an AES-256-GCM encrypted browser vault. PBKDF2-SHA-256 derives the unlock key from your password.</p><h2>Message encryption and sender authentication</h2><p>Messages combine ephemeral P-256 ECDH and ML-KEM-768. HKDF derives an AES-256-GCM key; ML-DSA-65 signs the message for sender verification.</p><h2>Identity exchange and file sharing</h2><p>Identity files contain public keys only. Message files contain signed ciphertext; message text and attachments are encrypted before sharing. Native file sharing and OS file opening depend on browser and platform support.</p><h2>Expiry, replay protection, and limits</h2><p>Messages expire after seven days and are marked as used after decryption. Text is limited to 10 KB and attachments to 50 KB.</p><h2>Standards and deployment</h2><p>ML-KEM-768 and ML-DSA-65 follow FIPS 203 and FIPS 204. Legacy links remain supported; their payload is stored in the URL fragment.</p><p><a class="info-link" href="./comparison.html">Compare Kriptal with messaging services <span aria-hidden="true">→</span></a></p>`
      : `<h1>How Kriptal works</h1><p class="lede">Kriptal exchanges encrypted message files directly between people. No server, cloud inbox, or message relay is used.</p><h2>1. Create your local identity</h2><p>Create a username and vault password. Your identity and contacts stay in an encrypted vault on this device.</p><h2>2. Exchange public identities</h2><p>Share your public-key file and import the contact's public key. Compare fingerprints using a trusted channel.</p><h2>3. Write and encrypt a message</h2><p>Choose a contact, write a message, and optionally attach a small file. Kriptal encrypts it for the recipient and signs it with your identity.</p><h2>4. Share and open the file</h2><p>Share the encrypted message file. The recipient opens it in Kriptal, verifies the sender, and decrypts it on their device. Messages expire after seven days.</p><p>Keep your device and password secure. Losing your password or browser storage means your identity cannot be recovered.</p>`;
    app.innerHTML = `<article class="info-page"><a class="back-link" href="./">← Back to Kriptal</a>${content}<div class="info-page-links"><a class="info-link" href="./faq.html">FAQ — simple explanations <span aria-hidden="true">→</span></a><a class="back-link" href="./landing.html">Kriptal overview</a></div><a class="back-link" href="./">Return to Kriptal</a></article>`;
    localizeElement(app);
  }

  async function setup(event) {
    event.preventDefault();
    const form = new FormData(event.target);
    const password = form.get('password');
    session = await newIdentity(form.get('username').trim());
    session.__password = password;
    await saveSession();
    toastMessage('Quantum-safe identity created on this device');
    renderApp();
  }

  async function upgradeIdentity(value, password) {
    if (value.kemPublicKey && value.signingPrivateKey) return { ...value, __password: password };
    const upgraded = {
      ...value,
      ...(await newIdentity(value.username)),
      contacts: (value.contacts || []).filter(
        (contact) => contact.kemPublicKey && contact.signingPublicKey
      )
    };
    upgraded.__password = password;
    await saveSession(upgraded);
    return upgraded;
  }

  async function unlock(event) {
    event.preventDefault();
    const password = new FormData(event.target).get('password');
    try {
      session = await upgradeIdentity(await decryptVault(storedRecord(), password), password);
      toastMessage('Vault unlocked');
      renderApp();
    } catch {
      toastMessage('That password does not unlock this vault');
    }
  }

  async function saveSession(value = session) {
    const clean = {
      username: value.username,
      publicKey: value.publicKey,
      privateKey: value.privateKey,
      signingPublicKey: value.signingPublicKey,
      signingPrivateKey: value.signingPrivateKey,
      kemPublicKey: value.kemPublicKey,
      kemSecretKey: value.kemSecretKey,
      contacts: value.contacts
    };
    storeRecord(await encryptVault(clean, value.__password));
    session = { ...clean, __password: value.__password };
  }

  function renderApp() {
    app.classList.remove('setup-screen');
    app.innerHTML = `<div class="dashboard"><aside class="side"><div class="user"><div class="section-label">Local identity</div><strong>${escapeHtml(session.username)}</strong><p class="section-label">ML-KEM-768 / P-256</p></div><nav aria-label="Main navigation"><button class="${view === 'compose' ? 'active' : ''}" data-view="compose" aria-label="Compose"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5 8 8 0 0 1-3.4-.8L4 20l1.8-4.1A7.5 7.5 0 1 1 20 11.5Z"/></svg><span class="nav-label">Compose</span></button><button class="${view === 'contacts' ? 'active' : ''}" data-view="contacts" aria-label="Contacts"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20v-1.5A5.5 5.5 0 0 1 8 13h2a5.5 5.5 0 0 1 5.5 5.5V20Zm12-15.5a3.5 3.5 0 0 1 0 7m2 2h.5a4.5 4.5 0 0 1 4.5 4.5V20h-3"/></svg><span class="nav-label">Contacts</span></button><button class="${view === 'open-message' ? 'active' : ''}" data-view="open-message" aria-label="Open message"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5 8 8 0 0 1-3.4-.8L4 20l1.8-4.1A7.5 7.5 0 1 1 20 11.5Z"/><path d="M9 11.5h7m-3-3 3 3-3 3"/></svg><span class="nav-label">Open message</span></button><button class="${view === 'identity' ? 'active' : ''}" data-view="identity" aria-label="Identity"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="9" cy="10" r="2.5"/><path d="M5.5 16a3.5 3.5 0 0 1 7 0m3-5h3m-3 3h3"/></svg><span class="nav-label">Identity</span></button></nav></aside><section id="workspace"></section></div>`;
    app
      .querySelector('nav[aria-label="Main navigation"]')
      .insertAdjacentHTML(
        'beforeend',
        `<button class="${view === 'settings' ? 'active' : ''}" data-view="settings" aria-label="Configuration"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-1.7 1.7-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2h-2.4v-.2a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.9.3l-.1.1L8 17l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H6.7v-2.4h.2a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.9L8 8.6l1.7-1.7.1.1a1.7 1.7 0 0 0 1.9.3 1.7 1.7 0 0 0 1-1.5v-.2h2.4v.2a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1 1.7 1.7-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.5 1h.2V14h-.2a1.7 1.7 0 0 0-1.5 1Z"/></svg><span class="nav-label">Configuration</span></button>`
      );
    localizeElement(app);
    app.querySelectorAll('[data-view]').forEach((button) =>
      button.addEventListener('click', () => {
        view = button.dataset.view;
        renderApp();
      })
    );
    if (view === 'compose') renderCompose();
    if (view === 'contacts') renderContacts();
    if (view === 'open-message') renderOpenMessage();
    if (view === 'identity') renderIdentity();
    if (view === 'settings') renderSettings();
    if (view === 'import') renderImportContact();
    openPendingLink();
    processLaunchFiles();
  }

  function openPendingLink() {
    if (pendingLinkOpened) return;
    pendingLinkOpened = true;
    const operation = routeMessage
      ? showDecrypt()
      : routeKey
        ? importContact(routeKey)
        : null;
    operation?.catch((error) => {
      console.error('Could not open the shared Kriptal link', error);
      toastMessage('Could not open this shared link');
    });
  }

  function renderCompose() {
    const options = session.contacts
      .map((contact, i) => {
        const sameName = session.contacts.filter(
          (item) => item.username === contact.username
        ).length > 1;
        const fingerprint = contact.fingerprint?.replaceAll(' ', '').slice(0, 8);
        const label = sameName
          ? `${contact.username} · ${fingerprint || `contact ${i + 1}`}`
          : contact.username;
        return `<option value="${i}">${escapeHtml(label)}</option>`;
      })
      .join('');
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Compose</div><h2>Make a private message</h2></div><div class="section-label">ML-KEM-768 / AES-256</div></div>${routeMessage ? `<div class="notice"><strong>Encrypted message detected.</strong> Verify the sender fingerprint against your saved contact before opening it.</div><div class="actions"><button id="decrypt-message">Verify & decrypt incoming message</button></div>` : ''}<form id="message-form"><div class="form-grid"><div><label for="recipient">Recipient</label><select id="recipient" required ${options ? '' : 'disabled'}><option value="">${options ? 'Choose a contact' : 'Add a contact first'}</option>${options}</select></div><div class="full"><label for="message">Message</label><textarea id="message" maxlength="10000" placeholder="Write something only your contact can read..." required></textarea></div><div class="full"><label for="attachment">Attach a file (max 50 KB)</label><input id="attachment" type="file"></div></div><div class="actions"><button type="submit" ${options ? '' : 'disabled'}>Encrypt & create file</button><button type="button" class="secondary" id="clear-message">Clear</button></div></form></section>`;
    document.querySelector('#message-form').addEventListener('submit', createMessage);
    document
      .querySelector('#clear-message')
      .addEventListener('click', () => document.querySelector('#message-form').reset());
    document.querySelector('#decrypt-message')?.addEventListener('click', showDecrypt);
  }

  function renderOpenMessage() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Open a private message</div><h2>Decrypt a message file</h2></div><div class="section-label">Verify before opening</div></div><p class="lede">Choose the encrypted Kriptal message file you received. The sender's identity and signature will be verified before the message is shown.</p><form id="message-file-form"><label for="message-file">Encrypted message file</label><input id="message-file" name="message-file" type="file" accept=".kriptalmsg,application/vnd.kriptal.encrypted-message+json,.json,application/json" required><div class="actions"><button type="submit">Decrypt</button></div></form></section>`;
    document
      .querySelector('#message-file-form')
      .addEventListener('submit', decryptMessageFile);
  }

  async function readExportFile(file, format) {
    if (file.size > 200000) throw new Error('The selected file is too large');
    const value = JSON.parse(await file.text());
    if (value?.format !== format || value.version !== 1)
      throw new Error('The selected file is not a supported Kriptal export');
    return value.payload;
  }

  async function openExportFile(file) {
    if (file.size > 200000) throw new Error('The selected file is too large');
    const value = JSON.parse(await file.text());
    if (value?.format === 'kriptal-public-identity') {
      await importContact(value.payload);
      return;
    }
    if (value?.format === 'kriptal-encrypted-message') {
      if (!validMessage(value.payload))
        throw new Error('This encrypted message file is expired or malformed');
      routeMessage = value.payload;
      await showDecrypt();
      return;
    }
    throw new Error('The selected file is not a supported Kriptal export');
  }

  async function processLaunchFiles() {
    if (!session || processingLaunchFiles || !pendingLaunchFiles.length) return;
    processingLaunchFiles = true;
    try {
      while (pendingLaunchFiles.length) {
        const handle = pendingLaunchFiles.shift();
        try {
          await openExportFile(await handle.getFile());
        } catch (error) {
          console.error('Could not open the Kriptal file launched by the operating system', error);
          toastMessage('Could not open that Kriptal file');
        }
      }
    } finally {
      processingLaunchFiles = false;
    }
  }

  async function decryptMessageFile(event) {
    event.preventDefault();
    const file = document.querySelector('#message-file').files[0];
    if (!file) return toastMessage('Choose an encrypted message file first');
    let payload;
    try {
      payload = await readExportFile(file, 'kriptal-encrypted-message');
    } catch (error) {
      console.error('Could not read the encrypted Kriptal message file', error);
      toastMessage('That is not a valid Kriptal message file');
      return;
    }
    if (!validMessage(payload))
      return toastMessage('This encrypted message file is expired or malformed');
    routeMessage = payload;
    await showDecrypt();
  }

  async function createMessage(event) {
    event.preventDefault();
    const form = event.target;
    const recipient = session.contacts[Number(form.querySelector('#recipient').value)];
    if (!recipient) return;
    const message = form.querySelector('#message').value;
    if (textEncoder.encode(message).length > MAX_MESSAGE_BYTES)
      return toastMessage('Message is too large');
    const file = form.querySelector('#attachment').files[0];
    if (file && file.size > MAX_FILE_BYTES) return toastMessage('File is too large for a message file');
    const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits'
    ]);
    const ephemeralPublic = await crypto.subtle.exportKey('jwk', ephemeral.publicKey);
    const salt = random(32);
    const kem = encapsulate(recipient.kemPublicKey);
    const key = await hybridKey(
      await sharedEcdh(
        await crypto.subtle.exportKey('jwk', ephemeral.privateKey),
        recipient.publicKey
      ),
      kem.sharedSecret,
      salt
    );
    const content = {
      message,
      file: file ? { name: file.name, type: file.type, data: b64(await file.arrayBuffer()) } : null
    };
    const encrypted = await encryptBytes(new TextEncoder().encode(JSON.stringify(content)), key);
    const unsigned = {
      v: VERSION,
      id: b64(random(16)),
      created: Date.now(),
      from: session.username,
      senderKey: session.publicKey,
      signingKey: session.signingPublicKey,
      recipientKey: recipient.publicKey,
      ephemeralKey: ephemeralPublic,
      kemCipherText: b64(kem.cipherText),
      salt: b64(salt),
      ...encrypted
    };
    const signature = await signPayload(unsigned, session.signingPrivateKey);
    const payload = { ...unsigned, signature };
    showFileShare(
      'Encrypted message file ready',
      'The message is encrypted and signed. Share this file with your recipient.',
      `${exportName(session.username)}-${fileDateTime()}.kriptalmsg`,
      'kriptal-encrypted-message',
      payload
    );
  }

  function renderContacts() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Your circle</div><h2>Contacts</h2></div><div class="section-label">${session.contacts.length} saved</div></div><div id="contact-list">${session.contacts.length ? session.contacts.map((contact, i) => `<div class="contact-row"><div class="contact-info"><div class="contact-initial">${escapeHtml(contact.username[0].toUpperCase())}</div><div><strong>${escapeHtml(contact.username)}</strong><p>${escapeHtml(contact.fingerprint || 'Fingerprint available after unlock')}</p></div></div><button class="danger" data-remove="${i}">Remove</button></div>`).join('') : '<div class="empty">Import a public-key file to start a private conversation.</div>'}</div><div class="actions"><button id="import-contact">Import public-key file</button></div></section>`;
    document.querySelector('#import-contact').addEventListener('click', openImportContact);
    app.querySelectorAll('[data-remove]').forEach((button) =>
      button.addEventListener('click', async () => {
        session.contacts.splice(Number(button.dataset.remove), 1);
        await saveSession();
        renderContacts();
        toastMessage('Contact removed');
      })
    );
  }

  function renderIdentity() {
    const identity = {
      v: VERSION,
      username: session.username,
      publicKey: session.publicKey,
      kemPublicKey: session.kemPublicKey,
      signingPublicKey: session.signingPublicKey
    };
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Your public identity</div><h2>Let someone add you</h2></div><div class="section-label">Public-key file</div></div><div class="identity-share"><p class="lede">Share this public-key file so a contact can add you and encrypt messages for you. It contains no private information.</p><div class="actions"><button id="share-key">Share public-key file</button><button class="secondary" id="download-key">Download public-key file</button></div></div></section>`;
    document.querySelector('#share-key').addEventListener('click', () =>
      shareExportFile(
        `${exportName(session.username)}.kriptalkey`,
        'kriptal-public-identity',
        identity,
        'Kriptal public identity',
        'Import this public-key file in Kriptal to add me as a contact.'
      )
    );
    document.querySelector('#download-key').addEventListener('click', () =>
      downloadExportFile(`${exportName(session.username)}.kriptalkey`, 'kriptal-public-identity', identity)
    );
  }

  function renderSettings() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Preferences & privacy</div><h2>Configuration</h2></div></div><div class="setting-row"><div><h3>Color theme</h3><p class="setting-description">Choose how Kriptal looks on this device.</p></div><label class="sr-only" for="theme-select">Color theme</label><select id="theme-select"><option value="dark" ${theme === 'dark' ? 'selected' : ''}>Dark</option><option value="light" ${theme === 'light' ? 'selected' : ''}>Light</option></select></div><div class="setting-row"><div><h3>Log out</h3><p class="setting-description">Lock your vault. Your identity and contacts will remain saved on this device.</p></div><button class="secondary" id="logout">Log out</button></div><div class="setting-row"><div><h3>Wipe all app data</h3><p class="setting-description">Permanently remove your local identity, contacts, settings, replay history, and offline app cache from this device.</p></div><button class="danger" id="wipe-data">Wipe all app data</button></div></section>`;
    localizeElement(document.querySelector('#workspace'));
    document.querySelector('#theme-select').addEventListener('change', (event) => {
      theme = event.target.value;
      localStorage.setItem('kriptal-theme', theme);
      window.applyKriptalTheme(theme);
    });
    document.querySelector('#logout').addEventListener('click', logout);
    document.querySelector('#wipe-data').addEventListener('click', wipeAppData);
  }

  function logout() {
    session = null;
    routeMessage = null;
    routeKey = null;
    pendingLaunchFiles.length = 0;
    view = 'compose';
    history.replaceState(null, '', location.pathname + location.search);
    renderSetup();
  }

  async function wipeAppData() {
    if (!confirm(translateText('Wipe all Kriptal app data on this device? Your identity and contacts cannot be recovered.', language))) return;
    try {
      if ('caches' in window) {
        const cacheNames = await caches.keys();
        await Promise.all(
          cacheNames
            .filter((name) => name.startsWith('kriptal-'))
            .map((name) => caches.delete(name))
        );
      }
      if ('serviceWorker' in navigator) {
        const appWorker = new URL(`${import.meta.env.BASE_URL}sw.js`, location.origin).href;
        const registrations = await navigator.serviceWorker.getRegistrations();
        const appRegistrations = registrations.filter((registration) =>
          [registration.active, registration.waiting, registration.installing]
            .filter(Boolean)
            .some((worker) => worker.scriptURL === appWorker)
        );
        await Promise.all(appRegistrations.map((registration) => registration.unregister()));
      }
      Object.keys(localStorage)
        .filter((key) => key.startsWith('kriptal'))
        .forEach((key) => localStorage.removeItem(key));
      sessionStorage.clear();
    } catch (error) {
      console.error('Could not wipe all Kriptal app data', error);
      toastMessage('Could not wipe all app data');
      return;
    }

    session = null;
    routeMessage = null;
    routeKey = null;
    pendingLaunchFiles.length = 0;
    view = 'compose';
    language = 'en';
    languageSelect.value = language;
    theme = 'dark';
    window.applyKriptalTheme(theme);
    history.replaceState(null, '', location.pathname + location.search);
    applyLanguage();
    renderSetup();
    toastMessage('All Kriptal app data was wiped');
  }

  function openImportContact() {
    view = 'import';
    renderApp();
    document.querySelector('#contact-file').focus();
  }

  function renderImportContact() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Add to your circle</div><h2>Import a public identity</h2></div><div class="section-label">Public-key file</div></div><p class="lede">Choose the public-key file your contact shared with you. It contains only public information.</p><form id="contact-import-form"><label for="contact-file">Public-key file</label><input id="contact-file" name="contact-file" type="file" accept=".kriptalkey,application/vnd.kriptal.public-key+json,.json,application/json" required><div class="actions"><button type="submit">Import contact</button><button type="button" class="secondary" id="cancel-contact-import">Cancel</button></div></form></section>`;
    document
      .querySelector('#contact-import-form')
      .addEventListener('submit', importContactFile);
    document.querySelector('#cancel-contact-import').addEventListener('click', () => {
      view = 'contacts';
      renderApp();
    });
  }

  async function importContactFile(event) {
    event.preventDefault();
    const file = document.querySelector('#contact-file').files[0];
    if (!file) return toastMessage('Choose a public-key file first');
    let payload;
    try {
      payload = await readExportFile(file, 'kriptal-public-identity');
    } catch (error) {
      console.error('Could not read the Kriptal public identity file', error);
      toastMessage('That is not a valid Kriptal public-key file');
      return;
    }
    await importContact(payload);
  }

  async function importContact(payload) {
    if (!validContact(payload))
      return toastMessage('That public key bundle is invalid or outdated');
    const isOwnIdentity =
      JSON.stringify(payload.publicKey) === JSON.stringify(session.publicKey) &&
      payload.kemPublicKey === session.kemPublicKey &&
      payload.signingPublicKey === session.signingPublicKey;
    if (isOwnIdentity) return toastMessage("That's your own identity");

    const isAlreadySaved = session.contacts.some(
      (contact) =>
        JSON.stringify(contact.publicKey) === JSON.stringify(payload.publicKey) &&
        contact.kemPublicKey === payload.kemPublicKey &&
        contact.signingPublicKey === payload.signingPublicKey
    );
    if (isAlreadySaved) {
      toastMessage('That contact is already saved');
      return;
    }
    const contact = {
      username: payload.username,
      publicKey: payload.publicKey,
      kemPublicKey: payload.kemPublicKey,
      signingPublicKey: payload.signingPublicKey
    };
    contact.fingerprint = await publicFingerprint(contact);
    session.contacts.push(contact);
    await saveSession();
    routeKey = null;
    if (!routeMessage) history.replaceState(null, '', location.pathname + location.search);
    view = 'contacts';
    renderApp();
    toastMessage(`${payload.username} added · ${contact.fingerprint}`);
    if (routeMessage) await showDecrypt();
  }

  async function showDecrypt() {
    if (!validMessage(routeMessage))
      return toastMessage('This encrypted message is expired or malformed');
    if (isReplayed(routeMessage.id)) return toastMessage('This message was already opened');
    const contact = session.contacts.find(
      (item) =>
        item.username === routeMessage.from &&
        JSON.stringify(item.publicKey) === JSON.stringify(routeMessage.senderKey) &&
        item.signingPublicKey === routeMessage.signingKey
    );
    if (!contact) {
      if (session.contacts.some((item) => item.username === routeMessage.from))
        return toastMessage('Sender key does not match the saved contact');
      return openImportContact();
    }
    if (JSON.stringify(routeMessage.recipientKey) !== JSON.stringify(session.publicKey))
      return toastMessage('This message is for another identity');
    try {
      const unsigned = { ...routeMessage };
      delete unsigned.signature;
      if (!(await verifyPayload(unsigned, routeMessage.signature, contact.signingPublicKey)))
        return toastMessage('Sender signature is invalid');
      const kemSecret = decapsulate(routeMessage.kemCipherText, session.kemSecretKey);
      const key = await hybridKey(
        await sharedEcdh(session.privateKey, routeMessage.ephemeralKey),
        kemSecret,
        bytes(routeMessage.salt)
      );
      const content = fromJson(new Uint8Array(await decryptBytes(routeMessage, key)));
      const messageFrom = routeMessage.from;
      markReplayed(routeMessage.id);
      routeMessage = null;
      history.replaceState(null, '', location.pathname + location.search);
      renderApp();
      let fileButton = '';
      if (content.file)
        fileButton = `<button id="download-file" class="secondary">Download ${escapeHtml(content.file.name)}</button>`;
      showModal(
        `<div class="section-label">Verified from ${escapeHtml(messageFrom)}</div><h2>Private message</h2><p class="lede">${escapeHtml(content.message).replaceAll('\n', '<br>')}</p><div class="notice">Sender fingerprint: ${escapeHtml(contact.fingerprint)}</div><div class="actions">${fileButton}<button class="secondary" id="close-modal">Close</button></div>`
      );
      document.querySelector('#download-file')?.addEventListener('click', () => {
        const blob = new Blob([bytes(content.file.data)], {
          type: content.file.type || 'application/octet-stream'
        });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = content.file.name;
        a.click();
      });
    } catch {
      toastMessage('This message could not be decrypted or authenticated');
    }
  }

  function showFileShare(title, description, fileName, format, payload) {
    showModal(
      `<div class="section-label">${escapeHtml(title)}</div><h2>Ready to share</h2><p class="lede">${escapeHtml(description)}</p><div class="notice">The message text and attachments are encrypted. The file also includes sender verification metadata.</div><div class="actions"><button id="share-message-file">Share message file</button><button id="download-message-file" class="secondary">Download file</button><button id="close-modal" class="secondary">Close</button></div>`
    );
    document.querySelector('#share-message-file').addEventListener('click', () =>
      shareExportFile(
        fileName,
        format,
        payload,
        'Kriptal encrypted message',
        'Open this encrypted message file in Kriptal.'
      )
    );
    document.querySelector('#download-message-file').addEventListener('click', () =>
      downloadExportFile(fileName, format, payload)
    );
  }

  function showModal(content) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `<div class="panel">${content}</div>`;
    localizeElement(modal);
    document.body.appendChild(modal);
    modal.querySelector('#close-modal')?.addEventListener('click', () => modal.remove());
    modal.addEventListener('click', (event) => {
      if (event.target === modal) {
        modal.remove();
      }
    });
  }

  function exportFile(fileName, format, payload) {
    const contents = JSON.stringify({ format, version: 1, payload }, null, 2);
    return new File([contents], fileName, { type: 'application/json' });
  }

  function exportName(name) {
    const safeName = name
      .normalize('NFKD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-zA-Z0-9_-]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 48);
    return safeName || 'contact';
  }

  function fileDateTime(date = new Date()) {
    const twoDigits = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}${twoDigits(date.getMonth() + 1)}${twoDigits(date.getDate())}-${twoDigits(date.getHours())}${twoDigits(date.getMinutes())}${twoDigits(date.getSeconds())}`;
  }

  function downloadExportFile(fileName, format, payload) {
    const file = exportFile(fileName, format, payload);
    const url = URL.createObjectURL(file);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toastMessage('File downloaded');
  }

  async function shareExportFile(fileName, format, payload, title, text) {
    const file = exportFile(fileName, format, payload);
    if (!navigator.share || !navigator.canShare?.({ files: [file] })) {
      toastMessage('System file sharing is unavailable in this browser. Use the download button instead.');
      return;
    }
    try {
      await navigator.share({ files: [file], title, text });
      toastMessage('File shared');
    } catch (error) {
      if (error.name === 'AbortError') return;
      console.error('Native file sharing failed', error);
      toastMessage('System file sharing is unavailable in this browser. Use the download button instead.');
    }
  }

  if ('serviceWorker' in navigator)
    window.addEventListener('load', () =>
      navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`)
    );
  renderSetup();
}
