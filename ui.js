import {
  VAULT_KEY,
  REPLAY_KEY,
  VERSION,
  MAX_MESSAGE_BYTES,
  MAX_FILE_BYTES,
  MAX_LINK_LENGTH,
  b64,
  bytes,
  fromJson,
  random,
  escapeHtml,
  readRoute,
  decodePayload,
  linkFor,
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

  function toastMessage(message) {
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2600);
  }

  function renderSetup() {
    const hasAccount = Boolean(storedRecord());
    app.innerHTML = `<section class="hero"><div><div class="eyebrow">Private communication, reimagined</div><h1>Your words.<br><em>Only your words.</em></h1><p class="lede">Kriptal turns messages and files into encrypted links. No inboxes, no accounts on a server, no trail to follow.</p></div><div class="hero-mark"><strong>Nothing leaves this device until you choose to share it.</strong></div></section><section class="panel auth-panel"><div class="panel-head"><div><div class="section-label">${hasAccount ? 'Welcome back' : 'Create your identity'}</div><h2>${hasAccount ? 'Unlock your vault' : 'Set up your local vault'}</h2></div><div class="section-label">01 / 03</div></div><div class="notice">Your password never leaves this browser. The vault uses AES-256-GCM. Messages use hybrid ML-KEM-768 + P-256 encryption and ML-DSA-65 sender authentication. There is no password reset.</div><form id="auth-form"><div class="form-grid">${!hasAccount ? '<div><label for="username">Your username</label><input id="username" name="username" required minlength="2" maxlength="32" placeholder="e.g. maren" autocomplete="username"></div>' : ''}<div class="${hasAccount ? 'full' : ''}"><label for="password">${hasAccount ? 'Vault password' : 'Choose a strong password'}</label><input id="password" name="password" type="password" required minlength="10" autocomplete="${hasAccount ? 'current-password' : 'new-password'}" placeholder="10 characters minimum"></div></div><div class="actions"><button type="submit">${hasAccount ? 'Unlock Kriptal' : 'Generate my identity'}</button>${hasAccount ? '<button type="button" class="danger" id="reset-account">Erase local vault</button>' : ''}</div></form></section>`;
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
    app.innerHTML = `<div class="dashboard"><aside class="side"><div class="user"><div class="section-label">Local identity</div><strong>${escapeHtml(session.username)}</strong><p class="section-label">ML-KEM-768 / P-256</p></div><nav aria-label="Main navigation"><button class="${view === 'compose' ? 'active' : ''}" data-view="compose" aria-label="Compose"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11.5a7.5 7.5 0 0 1-7.5 7.5 8 8 0 0 1-3.4-.8L4 20l1.8-4.1A7.5 7.5 0 1 1 20 11.5Z"/></svg><span class="nav-label">Compose</span></button><button class="${view === 'contacts' ? 'active' : ''}" data-view="contacts" aria-label="Contacts"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20v-1.5A5.5 5.5 0 0 1 8 13h2a5.5 5.5 0 0 1 5.5 5.5V20Zm12-15.5a3.5 3.5 0 0 1 0 7m2 2h.5a4.5 4.5 0 0 1 4.5 4.5V20h-3"/></svg><span class="nav-label">Contacts</span></button><button class="${view === 'identity' ? 'active' : ''}" data-view="identity" aria-label="Identity"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><rect x="3" y="4.5" width="18" height="15" rx="2"/><circle cx="9" cy="10" r="2.5"/><path d="M5.5 16a3.5 3.5 0 0 1 7 0m3-5h3m-3 3h3"/></svg><span class="nav-label">Identity</span></button></nav></aside><section id="workspace"></section></div>`;
    app.querySelectorAll('[data-view]').forEach((button) =>
      button.addEventListener('click', () => {
        view = button.dataset.view;
        renderApp();
      })
    );
    if (view === 'compose') renderCompose();
    if (view === 'contacts') renderContacts();
    if (view === 'identity') renderIdentity();
    if (view === 'import') renderImportContact();
    if (routeKey) importContact(routeKey);
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
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Compose</div><h2>Make a private link</h2></div><div class="section-label">ML-KEM-768 / AES-256</div></div>${routeMessage ? `<div class="notice"><strong>Encrypted link detected.</strong> Verify the sender fingerprint against your saved contact before opening it.</div><div class="actions"><button id="decrypt-message">Verify & decrypt incoming link</button></div>` : ''}<form id="message-form"><div class="form-grid"><div><label for="recipient">Recipient</label><select id="recipient" required ${options ? '' : 'disabled'}><option value="">${options ? 'Choose a contact' : 'Add a contact first'}</option>${options}</select></div><div><label for="subject">Label (optional)</label><input id="subject" maxlength="80" placeholder="A note to yourself"></div><div class="full"><label for="message">Message</label><textarea id="message" maxlength="10000" placeholder="Write something only your contact can read..." required></textarea></div><div class="full"><label for="attachment">Attach a file (max 50 KB)</label><input id="attachment" type="file"></div></div><div class="actions"><button type="submit" ${options ? '' : 'disabled'}>Encrypt & create link</button><button type="button" class="secondary" id="clear-message">Clear</button></div></form></section>`;
    document.querySelector('#message-form').addEventListener('submit', createMessage);
    document
      .querySelector('#clear-message')
      .addEventListener('click', () => document.querySelector('#message-form').reset());
    document.querySelector('#decrypt-message')?.addEventListener('click', showDecrypt);
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
    if (file && file.size > MAX_FILE_BYTES) return toastMessage('File is too large for a link');
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
    const link = linkFor('m', payload);
    if (link.length > MAX_LINK_LENGTH) return toastMessage('Generated link is too large');
    showLink(
      'Authenticated encrypted link ready',
      link,
      'The link expires in 7 days. Share it through any channel.'
    );
  }

  function renderContacts() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Your circle</div><h2>Contacts</h2></div><div class="section-label">${session.contacts.length} saved</div></div><div id="contact-list">${session.contacts.length ? session.contacts.map((contact, i) => `<div class="contact-row"><div class="contact-info"><div class="contact-initial">${escapeHtml(contact.username[0].toUpperCase())}</div><div><strong>${escapeHtml(contact.username)}</strong><p>${escapeHtml(contact.fingerprint || 'Fingerprint available after unlock')}</p></div></div><button class="danger" data-remove="${i}">Remove</button></div>`).join('') : '<div class="empty">No contacts yet. Import a public-key link to start a private conversation.</div>'}</div><div class="actions"><button id="import-contact">Import public key link</button></div></section>`;
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
    const publicLink = linkFor('k', {
      v: VERSION,
      username: session.username,
      publicKey: session.publicKey,
      kemPublicKey: session.kemPublicKey,
      signingPublicKey: session.signingPublicKey
    });
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Your public identity</div><h2>Let someone add you</h2></div><div class="section-label">Share by link</div></div><div class="identity-share"><p class="lede">Share your public key as a link. It contains no private information and lets a contact encrypt messages for you.</p><div class="code-box">${escapeHtml(publicLink)}</div><div class="actions"><button id="copy-key">Copy public link</button><button class="secondary" id="share-key">Share link</button></div></div></section>`;
    document.querySelector('#copy-key').addEventListener('click', () => copy(publicLink));
    document.querySelector('#share-key').addEventListener('click', () => share(publicLink));
  }

  function openImportContact() {
    view = 'import';
    renderApp();
    document.querySelector('#contact-link').focus();
  }

  function renderImportContact() {
    document.querySelector('#workspace').innerHTML =
      `<section class="panel"><div class="panel-head"><div><div class="section-label">Add to your circle</div><h2>Import a public identity</h2></div><div class="section-label">Link only</div></div><p class="lede">Paste the public-key link your contact shared with you. It contains only public information.</p><form id="contact-import-form"><label for="contact-link">Public-key link</label><textarea id="contact-link" name="contact-link" rows="5" required placeholder="Paste your contact's Kriptal public-key link"></textarea><div class="actions"><button type="button" class="secondary paste-button" id="paste-contact-link"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M8 4.5h8a2 2 0 0 1 2 2V20H6V6.5a2 2 0 0 1 2-2Z"/><path d="M9 4V3h6v1m-6 7h6m-6 3h6"/></svg>Paste link</button></div><div class="actions"><button type="submit">Import contact</button><button type="button" class="secondary" id="cancel-contact-import">Cancel</button></div></form></section>`;
    document
      .querySelector('#contact-import-form')
      .addEventListener('submit', submitContactImport);
    document
      .querySelector('#paste-contact-link')
      .addEventListener('click', pasteContactLink);
    document.querySelector('#cancel-contact-import').addEventListener('click', () => {
      view = 'contacts';
      renderApp();
    });
  }

  async function pasteContactLink() {
    try {
      if (!navigator.clipboard?.readText)
        throw new Error('Clipboard reading is not available in this browser');
      const value = await navigator.clipboard.readText();
      if (!value) return toastMessage('The clipboard is empty');
      document.querySelector('#contact-link').value = value.trim();
    } catch (error) {
      console.error('Could not read the public-key link from the clipboard', error);
      toastMessage('Could not read clipboard. Paste the link into the text box.');
    }
  }

  async function submitContactImport(event) {
    event.preventDefault();
    const value = document.querySelector('#contact-link').value.trim();
    let payload;
    try {
      const url = new URL(value);
      const encoded = new URLSearchParams(url.hash.slice(1)).get('k');
      if (!encoded) throw new Error('The link does not contain a public key');
      payload = decodePayload(encoded);
    } catch {
      toastMessage('That is not a valid Kriptal key link');
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
    if (isOwnIdentity) return toastMessage("That's your own identity link");

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
    history.replaceState(null, '', location.pathname);
    view = 'contacts';
    renderApp();
    toastMessage(`${payload.username} added · ${contact.fingerprint}`);
  }

  async function showDecrypt() {
    if (!validMessage(routeMessage))
      return toastMessage('This link is expired, malformed, or too large');
    if (isReplayed(routeMessage.id)) return toastMessage('This message link was already opened');
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
      markReplayed(routeMessage.id);
      let fileButton = '';
      if (content.file)
        fileButton = `<button id="download-file" class="secondary">Download ${escapeHtml(content.file.name)}</button>`;
      showModal(
        `<div class="section-label">Verified from ${escapeHtml(routeMessage.from)}</div><h2>${escapeHtml(content.subject || 'Private message')}</h2><p class="lede">${escapeHtml(content.message).replaceAll('\n', '<br>')}</p><div class="notice">Sender fingerprint: ${escapeHtml(contact.fingerprint)}</div><div class="actions">${fileButton}<button class="secondary" id="close-modal">Close</button></div>`
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

  function showLink(title, link, copyText) {
    showModal(
      `<div class="section-label">${escapeHtml(title)}</div><h2>One link. Nothing else.</h2><p class="lede">${escapeHtml(copyText)}</p><div class="code-box">${escapeHtml(link)}</div><div class="actions"><button id="copy-result">Copy link</button><button id="share-result" class="secondary">Share</button><button id="close-modal" class="secondary">Close</button></div>`
    );
    document.querySelector('#copy-result').addEventListener('click', () => copy(link));
    document.querySelector('#share-result').addEventListener('click', () => share(link));
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

  async function copy(value) {
    await navigator.clipboard.writeText(value);
    toastMessage('Copied to clipboard');
  }

  async function share(value) {
    if (navigator.share) await navigator.share({ title: 'Kriptal private link', text: value });
    else copy(value);
  }

  if ('serviceWorker' in navigator)
    window.addEventListener('load', () =>
      navigator.serviceWorker.register(`${import.meta.env.BASE_URL}sw.js`)
    );
  renderSetup();
}
