import { test, expect } from '@playwright/test';
import {
  b64,
  decodePayload,
  encodeIdentityPayload,
  encodeMessagePayload,
  encodePayload
} from '../common.js';

const password = 'correct horse battery staple';

test('compact public identity links are smaller and legacy links still decode', () => {
  const payload = {
    v: 2,
    username: 'MatiCelu',
    publicKey: {
      crv: 'P-256',
      ext: true,
      key_ops: [],
      kty: 'EC',
      x: b64(new Uint8Array(32)),
      y: b64(new Uint8Array(32))
    },
    kemPublicKey: b64(new Uint8Array(1184)),
    signingPublicKey: b64(new Uint8Array(1952))
  };
  const compact = encodeIdentityPayload(payload);
  const legacy = encodePayload(payload);

  expect(compact.length).toBeLessThan(legacy.length);
  expect(
    `https://matiasdieguez.github.io/kriptal-app/#k=${compact}`.length
  ).toBeLessThanOrEqual(4096);
  expect(decodePayload(compact)).toEqual(payload);
  const link = `https://matiasdieguez.github.io/kriptal-app/#k=${compact}`;
  expect(decodePayload(new URLSearchParams(new URL(link).hash.slice(1)).get('k'))).toEqual(payload);
  expect(decodePayload(legacy)).toEqual(payload);
});

test('compact message links round-trip through URL parsing and retain legacy support', () => {
  const key = () => ({
    crv: 'P-256',
    ext: true,
    key_ops: [],
    kty: 'EC',
    x: b64(new Uint8Array(32)),
    y: b64(new Uint8Array(32))
  });
  const payload = {
    v: 2,
    id: b64(new Uint8Array(16)),
    created: 1793560000000,
    from: 'sender',
    senderKey: key(),
    signingKey: b64(new Uint8Array(1952)),
    recipientKey: key(),
    ephemeralKey: key(),
    kemCipherText: b64(new Uint8Array(1088)),
    salt: b64(new Uint8Array(32)),
    iv: b64(new Uint8Array(12)),
    data: b64(new Uint8Array(1200)),
    signature: b64(new Uint8Array(3309))
  };
  const compact = encodeMessagePayload(payload);
  const legacy = encodePayload(payload);
  const link = `https://matiasdieguez.github.io/kriptal-app/#m=${compact}`;
  const encoded = new URLSearchParams(new URL(link).hash.slice(1)).get('m');

  expect(compact.length).toBeLessThan(legacy.length);
  expect(decodePayload(encoded)).toEqual(payload);
  expect(decodePayload(legacy)).toEqual(payload);
});

test('home provides readable how-it-works and technical security pages', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: /How Kriptal works/ }).click();
  await expect(page.getByRole('heading', { name: 'How Kriptal works' })).toBeVisible();
  await expect(page.getByText(/No server, cloud inbox, or message relay/)).toBeVisible();
  await page.getByRole('link', { name: '← Back to Kriptal' }).click();
  await page.getByRole('link', { name: /Security & technical details/ }).click();
  await expect(page.getByRole('heading', { name: 'Security and technical details' })).toBeVisible();
  await expect(page.getByText(/PBKDF2-SHA-256/)).toBeVisible();
  await expect(page.getByText(/ML-KEM-768/).first()).toBeVisible();
  await expect(page.locator('meta[name="description"]')).toHaveAttribute(
    'content',
    /Technical overview of Kriptal security/
  );
  await expect(page.getByRole('link', { name: /Compare Kriptal with messaging services/ })).toHaveAttribute(
    'href',
    './comparison.html'
  );
});

test('home links to legal notice, repository, and sourced product comparison', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('link', { name: /Legal & disclaimer/ })).toHaveAttribute(
    'href',
    './legal.html'
  );
  await expect(page.getByRole('link', { name: /GitHub repository/ })).toHaveAttribute(
    'href',
    'https://github.com/matiasdieguez/kriptal-app'
  );

  await page.goto('/legal.html');
  await expect(page.getByRole('heading', { name: 'Legal notice and disclaimer' })).toBeVisible();
  await expect(page.getByText(/To the maximum extent permitted by applicable law/)).toBeVisible();
  await expect(page.getByRole('link', { name: 'Kriptal GitHub repository' })).toHaveAttribute(
    'href',
    'https://github.com/matiasdieguez/kriptal-app'
  );

  await page.goto('/comparison.html');
  await expect(page.getByRole('heading', { name: 'Encrypted messaging tools: a practical comparison' })).toBeVisible();
  await expect(page.getByRole('table')).toContainText('Cloud Chats are not end-to-end encrypted by default');
  await expect(page.getByRole('link', { name: /Signal — official product information/ })).toHaveAttribute(
    'href',
    'https://signal.org/'
  );
});

test('language selector translates the home page and information pages in all supported languages', async ({ page }) => {
  const expected = {
    en: 'How Kriptal works',
    es: 'Cómo funciona Kriptal',
    it: 'Come funziona Kriptal',
    pt: 'Como o Kriptal funciona',
    nl: 'Hoe Kriptal werkt',
    fr: 'Comment fonctionne Kriptal',
    zh: 'Kriptal 的工作方式',
    ja: 'Kriptal の使い方',
    ru: 'Как работает Kriptal',
    eo: 'Kiel Kriptal funkcias'
  };
  const expectedHeadline = {
    en: 'Your messages, secured',
    es: 'Tus mensajes, protegidos',
    it: 'I tuoi messaggi, al sicuro',
    pt: 'Suas mensagens, protegidas',
    nl: 'Je berichten, beveiligd',
    fr: 'Vos messages, sécurisés',
    zh: '你的消息，安全无忧',
    ja: 'あなたのメッセージを、安全に',
    ru: 'Ваши сообщения под защитой',
    eo: 'Viaj mesaĝoj, sekurigitaj'
  };
  const expectedTagline = {
    en: 'Privacy is a Human Right',
    es: 'La privacidad es un derecho humano',
    it: 'La privacy è un diritto umano',
    pt: 'A privacidade é um direito humano',
    nl: 'Privacy is een mensenrecht',
    fr: 'La vie privée est un droit humain',
    zh: '隐私是一项人权',
    ja: 'プライバシーは人権です',
    ru: 'Конфиденциальность — это право человека',
    eo: 'Privateco estas homa rajto'
  };
  const expectedLandingLink = {
    en: 'Learn about Kriptal',
    es: 'Conoce Kriptal',
    it: 'Scopri Kriptal',
    pt: 'Conheça o Kriptal',
    nl: 'Meer over Kriptal',
    fr: 'Découvrir Kriptal',
    zh: '了解 Kriptal',
    ja: 'Kriptal について',
    ru: 'Узнайте о Kriptal',
    eo: 'Pri Kriptal'
  };
  await page.goto('/');
  for (const [language, linkName] of Object.entries(expected)) {
    await page.locator('#language-select').selectOption(language);
    await expect(page.locator('.landing-nav-link')).toHaveText(expectedLandingLink[language]);
    await expect(page.locator('.setup-intro .eyebrow')).toHaveText(expectedTagline[language]);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(expectedHeadline[language]);
    await expect(page.locator('html')).toHaveAttribute(
      'lang',
      language === 'zh' ? 'zh-CN' : language
    );
    await expect(page.locator('a[href="?page=how-it-works"]')).toContainText(linkName);
    if (language === 'es') {
      await page.getByLabel('Tu nombre de usuario').fill('maren');
      await page.getByLabel('Elige una contraseña segura').fill(password);
    }
    if (language === 'it') {
      await expect(page.getByLabel('Il tuo nome utente')).toHaveValue('maren');
      await expect(page.getByLabel('Scegli una password sicura')).toHaveValue(password);
    }
  }
  await page.locator('#language-select').selectOption('es');
  await page.locator('a[href="?page=how-it-works"]').click();
  await expect(page.getByRole('heading', { name: 'Cómo funciona Kriptal' })).toBeVisible();
  await expect(page.getByText(/Kriptal intercambia archivos de mensajes cifrados/)).toBeVisible();
  await page.reload();
  await expect(page.locator('#language-select')).toHaveValue('es');
});

test('landing page explains security, installation, and use with working illustrations', async ({ page }) => {
  await page.goto('/landing.html');
  await expect(page).toHaveTitle('Privacy is a Human Right | Kriptal');
  await expect(page.getByRole('heading', { name: 'Your keys stay yours.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Good security is a shared habit.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Make Kriptal an app.' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'From first setup to a verified message.' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Tor Project ↗' })).toHaveAttribute('href', 'https://www.torproject.org/');
  await expect(page.getByRole('link', { name: 'Open Kriptal' }).first()).toHaveAttribute('href', './');
  await expect(page.locator('.landing-section img')).toHaveCount(4);
  for (const image of await page.locator('.landing-section img').all()) {
    await expect(image).toHaveJSProperty('complete', true);
    await expect.poll(() => image.evaluate((element) => element.naturalWidth)).toBeGreaterThan(0);
  }
});

async function createIdentity(page, username) {
  await page.goto('/');
  await page.getByLabel('Your username').fill(username);
  await page.getByLabel('Choose a strong password').fill(password);
  await page.getByRole('button', { name: 'Generate my identity' }).click();
  await expect(page.locator('.user strong')).toHaveText(username);
}

async function enableNativeFileShare(page) {
  await page.addInitScript(() => {
    window.__sharedFiles = [];
    window.__launchConsumer = null;
    Object.defineProperty(window, 'launchQueue', {
      configurable: true,
      value: {
        setConsumer: (consumer) => {
          window.__launchConsumer = consumer;
        }
      }
    });
    Object.defineProperty(navigator, 'canShare', {
      configurable: true,
      value: ({ files }) => Array.isArray(files) && files.length > 0
    });
    Object.defineProperty(navigator, 'share', {
      configurable: true,
      value: async ({ files }) => {
        const shared = await Promise.all(
          files.map(async (file) => ({
            name: file.name,
            type: file.type,
            contents: await file.text()
          }))
        );
        window.__sharedFiles.push(...shared);
      }
    });
  });
}

async function launchFileToApp(page, file) {
  await page.evaluate(async ({ name, contents }) => {
    await window.__launchConsumer({
      files: [
        {
          getFile: async () =>
            new File([contents], name, {
              type: name.endsWith('.kriptalkey')
                ? 'application/vnd.kriptal.public-key+json'
                : 'application/vnd.kriptal.encrypted-message+json'
            })
        }
      ]
    });
  }, file);
}

async function shareIdentityFile(page) {
  await page.getByRole('button', { name: 'Identity' }).click();
  await page.getByRole('button', { name: 'Share public-key file' }).click();
  await expect.poll(() => page.evaluate(() => window.__sharedFiles.length)).toBeGreaterThan(0);
  return page.evaluate(() => window.__sharedFiles.pop());
}

async function importContact(page, identityFile) {
  await page.getByRole('button', { name: 'Contacts' }).click();
  await page.getByRole('button', { name: 'Import public-key file' }).click();
  await expect(page.getByRole('heading', { name: 'Import a public identity' })).toBeVisible();
  await page.getByLabel('Public-key file').setInputFiles({
    name: identityFile.name,
    mimeType: 'application/json',
    buffer: Buffer.from(identityFile.contents)
  });
  await page.getByRole('button', { name: 'Import contact' }).click();
}

test('creates a local identity and unlocks it after reload', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.locator('.hero-mark')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollHeight)).toBeLessThanOrEqual(
    844
  );
  await page.getByLabel('Your username').fill('maren');
  await page.getByLabel('Choose a strong password').fill(password);
  await page.getByRole('button', { name: 'Generate my identity' }).click();
  await expect(page.locator('.user strong')).toHaveText('maren');

  await page.setViewportSize({ width: 1280, height: 900 });
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await expect(nav.getByText('Compose')).toBeVisible();
  await expect(nav.locator('.nav-icon')).toHaveCount(5);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(nav.getByText('Compose')).toBeHidden();
  await expect(nav.locator('.nav-icon').first()).toBeVisible();
  await expect(nav.getByRole('button', { name: 'Contacts' })).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await page.getByLabel('Vault password').fill(password);
  await page.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await expect(page.locator('.user strong')).toHaveText('maren');

  await context.close();
});

test('defaults to dark theme and configures theme, logout, and app-data wipe', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => localStorage.getItem('kriptal-theme'))).toBeNull();
  await createIdentity(page, 'settings-user');
  await page.locator('#language-select').selectOption('es');
  await page.getByRole('button', { name: 'Configuración' }).click();
  await expect(page.getByRole('heading', { name: 'Configuración' })).toBeVisible();
  await page.getByLabel('Tema de color').selectOption('light');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(245, 241, 232)');
  await page.locator('#language-select').selectOption('en');

  await page.goto('/legal.html');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.goto('/');
  await page.getByLabel('Vault password').fill(password);
  await page.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await page.getByRole('button', { name: 'Configuration' }).click();
  await page.getByRole('button', { name: 'Log out' }).click();
  await expect(page.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  expect(await page.evaluate(() => Boolean(localStorage.getItem('kriptal.vault')))).toBe(true);

  await page.getByLabel('Vault password').fill(password);
  await page.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await page.getByRole('button', { name: 'Configuration' }).click();
  await page.evaluate(async () => {
    localStorage.setItem('kriptal.extra', 'test');
    sessionStorage.setItem('session-data', 'test');
    const cache = await caches.open('kriptal-test');
    await cache.put('/app-data-test', new Response('cached'));
  });
  page.once('dialog', (dialog) => dialog.accept());
  await page.getByRole('button', { name: 'Wipe all app data' }).click();
  await expect(page.getByRole('heading', { name: 'Set up your local vault' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('kriptal')))).toEqual([]);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  expect(await page.evaluate(async () => (await caches.keys()).filter((name) => name.startsWith('kriptal-')))).toEqual([]);
});

test('toast text remains dark and legible in both themes', async ({ page }) => {
  await page.goto('/');
  const toast = page.locator('#toast');
  await expect(toast).toHaveCSS('color', 'rgb(28, 39, 36)');
  await expect(toast).toHaveCSS('background-color', 'rgb(228, 201, 107)');

  await page.evaluate(() => {
    localStorage.setItem('kriptal-theme', 'light');
  });
  await page.reload();
  await expect(toast).toHaveCSS('color', 'rgb(28, 39, 36)');
  await expect(toast).toHaveCSS('background-color', 'rgb(244, 211, 107)');
});

test('share action reports unsupported system sharing instead of silently downloading', async ({ page }) => {
  await page.addInitScript(() => {
    window.__downloadCount = 0;
    Object.defineProperty(navigator, 'share', { configurable: true, value: undefined });
    Object.defineProperty(navigator, 'canShare', { configurable: true, value: undefined });
    HTMLAnchorElement.prototype.click = function () {
      if (this.hasAttribute('download')) window.__downloadCount += 1;
    };
  });
  await createIdentity(page, 'share-test');
  await page.getByRole('button', { name: 'Identity' }).click();
  await page.getByRole('button', { name: 'Share public-key file' }).click();
  await expect(page.locator('#toast')).toContainText('System file sharing is unavailable');
  expect(await page.evaluate(() => window.__downloadCount)).toBe(0);
});

test('shares public-key files and decrypts an encrypted message file', async ({ browser }) => {
  const aliceContext = await browser.newContext();
  const bobContext = await browser.newContext();
  const alice = await aliceContext.newPage();
  const bob = await bobContext.newPage();
  await enableNativeFileShare(alice);
  await enableNativeFileShare(bob);

  await createIdentity(alice, 'alice');
  const aliceIdentityFile = await shareIdentityFile(alice);
  expect(aliceIdentityFile.name).toBe('alice.kriptalkey');
  expect(aliceIdentityFile.type).toBe('application/json');

  await createIdentity(bob, 'bob');
  const bobIdentityFile = await shareIdentityFile(bob);

  expect(bobIdentityFile.name).toBe('bob.kriptalkey');
  await launchFileToApp(alice, bobIdentityFile);
  await expect(alice.locator('.contact-row strong')).toHaveText('bob');

  await importContact(bob, aliceIdentityFile);
  await expect(bob.locator('.contact-row strong')).toHaveText('alice');

  await bob.getByRole('button', { name: 'Compose' }).click();
  await bob.locator('#recipient').selectOption({ label: 'alice' });
  await expect(bob.locator('#subject')).toHaveCount(0);
  await bob.locator('#message').fill('A message only Alice can read.');
  await bob.getByRole('button', { name: 'Encrypt & create file' }).click();
  await expect(bob.locator('.modal')).toBeVisible();
  await bob.getByRole('button', { name: 'Share message file' }).click();
  await expect.poll(() => bob.evaluate(() => window.__sharedFiles.length)).toBeGreaterThan(0);
  const messageFile = await bob.evaluate(() => window.__sharedFiles.pop());
  expect(messageFile.name).toMatch(/^bob-\d{8}-\d{6}\.kriptalmsg$/);
  expect(messageFile.type).toBe('application/json');

  const incoming = await aliceContext.newPage();
  await enableNativeFileShare(incoming);
  await incoming.goto('/');
  await expect(incoming.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await incoming.getByLabel('Vault password').fill(password);
  await incoming.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await launchFileToApp(incoming, messageFile);
  await expect(incoming.getByText('Verified from bob')).toBeVisible();
  await expect(incoming.getByText('A message only Alice can read.')).toBeVisible();

  await aliceContext.close();
  await bobContext.close();
});

test('imports public-key files into an existing vault and exposes contacts to compose', async ({ browser }) => {
  const aliceContext = await browser.newContext();
  const secondAliceContext = await browser.newContext();
  const bobContext = await browser.newContext();
  const alice = await aliceContext.newPage();
  const secondAlice = await secondAliceContext.newPage();
  const bob = await bobContext.newPage();
  await enableNativeFileShare(alice);
  await enableNativeFileShare(secondAlice);

  await createIdentity(alice, 'alice');
  const aliceIdentityFile = await shareIdentityFile(alice);

  await createIdentity(secondAlice, 'alice');
  const secondAliceIdentityFile = await shareIdentityFile(secondAlice);

  await createIdentity(bob, 'bob');
  const bobImportPage = await bobContext.newPage();
  await enableNativeFileShare(bobImportPage);
  await bobImportPage.goto('/');
  await expect(bobImportPage.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await bobImportPage.getByLabel('Vault password').fill(password);
  await bobImportPage.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await importContact(bobImportPage, aliceIdentityFile);
  await expect(bobImportPage.locator('.contact-row strong')).toHaveText('alice');

  await bobImportPage.getByRole('button', { name: 'Compose' }).click();
  await expect(bobImportPage.locator('#recipient option', { hasText: 'alice' })).toHaveCount(1);

  await importContact(bobImportPage, secondAliceIdentityFile);
  await expect(bobImportPage.locator('.contact-row strong')).toHaveCount(2);
  await bobImportPage.getByRole('button', { name: 'Compose' }).click();
  await expect(bobImportPage.locator('#recipient option')).toHaveCount(3);
  await expect(bobImportPage.locator('#recipient option').filter({ hasText: /alice ·/ })).toHaveCount(2);

  await bobImportPage.reload();
  await bobImportPage.getByLabel('Vault password').fill(password);
  await bobImportPage.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await bobImportPage.getByRole('button', { name: 'Compose' }).click();
  await expect(bobImportPage.locator('#recipient option').filter({ hasText: /alice ·/ })).toHaveCount(2);

  await aliceContext.close();
  await secondAliceContext.close();
  await bobContext.close();
});
