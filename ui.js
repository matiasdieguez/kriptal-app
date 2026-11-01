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

export function initUI({ app, toast }) {
  const textEncoder = new TextEncoder();
  let session = null;
  let view = 'compose';
  let routeMessage = readRoute('m');
  let routeKey = readRoute('k');
  let pendingLinkOpened = false;
  const pendingLaunchFiles = [];
  let processingLaunchFiles = false;

  function toastMessage(message) {
    toast.textContent = message;
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
    const hasAccount = Boolean(storedRecord());
    app.innerHTML = `<section class="hero"><div><div class="eyebrow">Private communication, reimagined</div><h1>Your words.<br><em>Only your words.</em></h1><p class="lede">Kriptal encrypts messages and files for sharing. No inboxes, no accounts on a server, no trail to follow.</p></div><div class="hero-mark"><strong>Nothing leaves this device until you choose to share it.</strong></div></section><section class="panel auth-panel"><div class="panel-head"><div><div class="section-label">${hasAccount ? 'Welcome back' : 'Create your identity'}</div><h2>${hasAccount ? 'Unlock your vault' : 'Set up your local vault'}</h2></div><div class="section-label">01 / 03</div></div><div class="notice">Your password never leaves this browser. The vault uses AES-256-GCM. Messages use hybrid ML-KEM-768 + P-256 encryption and ML-DSA-65 sender authentication. There is no password reset.</div><form id="auth-form"><div class="form-grid">${!hasAccount ? '<div><label for="username">Your username</label><input id="username" name="username" required minlength="2" maxlength="32" placeholder="e.g. maren" autocomplete="username"></div>' : ''}<div class="${hasAccount ? 'full' : ''}"><label for="password">${hasAccount ? 'Vault password' : 'Choose a strong password'}</label><input id="password" name="password" type="password" required minlength="10" autocomplete="${hasAccount ? 'current-password' : 'new-password'}" placeholder="10 characters minimum"></div></div><div class="actions"><button type="submit">${hasAccount ? 'Unlock Kriptal' : 'Generate my identity'}</button>${hasAccount ? '<button type="button" class="danger" id="reset-account">Erase local vault</button>' : ''}</div></form></section>`;
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
    app.innerHTML = `<div class="dashboard"><aside class="side"><div class="user"><div class="section-label">Local identity</div><strong>${escapeHtml(session.username)}</strong><p class="section-label">ML-KEM-768 / P-256</p></div><nav aria-label="Main navigation"><button class="${view === 'compose' ? 'active' : ''}" data-view="compose" aria-label="Compose"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5 8 8 0 0 1-3.4-.8L4 20l1.8-4.1A7.5 7.5 0 1 1 20 11.5Z"/></svg><span class="nav-label">Compose</span></button><button class="${view === 'contacts' ? 'active' : ''}" data-view="contacts" aria-label="Contacts"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20v-1.5A5.5 5.5 0 0 1 8 13h2a5.5 5.5 0 0 1 5.5 5.5V20Zm12-15.5a3.5 3.5 0 0 1 0 7m2 2h.5a4.5 4.5 0 0 1 4.5 4.5V20h-3"/></svg><span class="nav-label">Contacts</span></button><button class="${view === 'open-message' ? 'active' : ''}" data-view="open-message" aria-label="Open message"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5 8 8 0 0 1-3.4-.8L4 20l1.8-4.1A7.5 7.5 0 1 1 20 11.5Z"/><path d="M9 11.5h7m-3-3 3 3-3 3"/></svg><span class="nav-label">Open message</span></button><button class="${view === 'identity' ? 'active' : ''}" data-view="identity" aria-label="Identity"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="9" cy="10" r="2.5"/><path d="M5.5 16a3.5 3.5 0 0 1 7 0m3-5h3m-3 3h3"/></svg><span class="nav-label">Identity</span></button></nav></aside><section id="workspace"></section></div>`;
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
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Compose</div><h2>Make a private message</h2></div><div class="section-label">ML-KEM-768 / AES-256</div></div>${routeMessage ? `<div class="notice"><strong>Encrypted message detected.</strong> Verify the sender fingerprint against your saved contact before opening it.</div><div class="actions"><button id="decrypt-message">Verify & decrypt incoming message</button></div>` : ''}<form id="message-form"><div class="form-grid"><div><label for="recipient">Recipient</label><select id="recipient" required ${options ? '' : 'disabled'}><option value="">${options ? 'Choose a contact' : 'Add a contact first'}</option>${options}</select></div><div><label for="subject">Label (optional)</label><input id="subject" maxlength="80" placeholder="A note to yourself"></div><div class="full"><label for="message">Message</label><textarea id="message" maxlength="10000" placeholder="Write something only your contact can read..." required></textarea></div><div class="full"><label for="attachment">Attach a file (max 50 KB)</label><input id="attachment" type="file"></div></div><div class="actions"><button type="submit" ${options ? '' : 'disabled'}>Encrypt & create file</button><button type="button" class="secondary" id="clear-message">Clear</button></div></form></section>`;
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
      subject: form.querySelector('#subject').value,
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
        `<div class="section-label">Verified from ${escapeHtml(messageFrom)}</div><h2>${escapeHtml(content.subject || 'Private message')}</h2><p class="lede">${escapeHtml(content.message).replaceAll('\n', '<br>')}</p><div class="notice">Sender fingerprint: ${escapeHtml(contact.fingerprint)}</div><div class="actions">${fileButton}<button class="secondary" id="close-modal">Close</button></div>`
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
    const type =
      format === 'kriptal-public-identity'
        ? 'application/vnd.kriptal.public-key+json'
        : 'application/vnd.kriptal.encrypted-message+json';
    return new File([contents], fileName, { type });
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
      downloadExportFile(fileName, format, payload);
      return;
    }
    try {
      await navigator.share({ files: [file], title, text });
      toastMessage('File shared');
    } catch (error) {
      if (error.name === 'AbortError') return;
      console.error('Native file sharing failed', error);
      downloadExportFile(fileName, format, payload);
    }
  }

  if ('serviceWorker' in navigator)
    window.addEventListener('load', () =>
      navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`)
    );
  renderSetup();
}
