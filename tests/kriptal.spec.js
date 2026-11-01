import { test, expect } from '@playwright/test';
import { b64, decodePayload, encodeIdentityPayload, encodePayload } from '../common.js';

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

async function createIdentity(page, username) {
  await page.goto('/');
  await page.getByLabel('Your username').fill(username);
  await page.getByLabel('Choose a strong password').fill(password);
  await page.getByRole('button', { name: 'Generate my identity' }).click();
  await expect(page.locator('.user strong')).toHaveText(username);
}

async function importContact(page, link, pasteFromClipboard = false) {
  await page.getByRole('button', { name: 'Contacts' }).click();
  await page.getByRole('button', { name: 'Import public key link' }).click();
  await expect(page.getByRole('heading', { name: 'Import a public identity' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Paste link' })).toBeVisible();
  if (pasteFromClipboard) {
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
    await page.evaluate((value) => navigator.clipboard.writeText(value), link);
    await page.getByRole('button', { name: 'Paste link' }).click();
    await expect(page.getByLabel('Public-key link')).toHaveValue(link.trim());
  } else {
    await page.getByLabel('Public-key link').fill(link);
  }
  await page.getByRole('button', { name: 'Import contact' }).click();
}

test('creates a local identity and unlocks it after reload', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();

  await createIdentity(page, 'maren');
  const nav = page.getByRole('navigation', { name: 'Main navigation' });
  await expect(nav.getByText('Compose')).toBeVisible();
  await expect(nav.locator('.nav-icon')).toHaveCount(4);
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

test('exchanges identities and decrypts an encrypted message link', async ({ browser }) => {
  const aliceContext = await browser.newContext();
  const bobContext = await browser.newContext();
  const alice = await aliceContext.newPage();
  const bob = await bobContext.newPage();

  await createIdentity(alice, 'alice');
  await alice.getByRole('button', { name: 'Identity' }).click();
  const aliceIdentityLink = await alice.locator('.code-box').innerText();

  await createIdentity(bob, 'bob');
  await bob.getByRole('button', { name: 'Identity' }).click();
  const bobIdentityLink = await bob.locator('.code-box').innerText();

  await importContact(alice, `  ${bobIdentityLink}\n`, true);
  await expect(alice.locator('.contact-row strong')).toHaveText('bob');

  await importContact(bob, aliceIdentityLink);
  await expect(bob.locator('.contact-row strong')).toHaveText('alice');

  await bob.getByRole('button', { name: 'Compose' }).click();
  await bob.locator('#recipient').selectOption({ label: 'alice' });
  await bob.locator('#message').fill('A message only Alice can read.');
  await bob.getByRole('button', { name: 'Encrypt & create link' }).click();
  await expect(bob.locator('.modal')).toBeVisible();
  const messageLink = await bob.locator('.modal .code-box').innerText();
  expect(messageLink).toContain('#m=');

  const incoming = await aliceContext.newPage();
  await incoming.goto('/');
  await expect(incoming.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await incoming.getByLabel('Vault password').fill(password);
  await incoming.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await incoming.getByRole('button', { name: 'Open message' }).click();
  await expect(incoming.getByRole('heading', { name: 'Decrypt a message link' })).toBeVisible();
  await incoming.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  await incoming.evaluate((value) => navigator.clipboard.writeText(value), messageLink);
  await incoming.getByRole('button', { name: 'Paste link' }).click();
  await expect(incoming.getByLabel('Encrypted message link')).toHaveValue(messageLink);
  await incoming.getByRole('button', { name: 'Decrypt', exact: true }).click();
  await expect(incoming.getByText('Verified from bob')).toBeVisible();
  await expect(incoming.getByText('A message only Alice can read.')).toBeVisible();

  await aliceContext.close();
  await bobContext.close();
});

test('imports a public-key link into an existing vault and exposes it to compose', async ({ browser }) => {
  const aliceContext = await browser.newContext();
  const secondAliceContext = await browser.newContext();
  const bobContext = await browser.newContext();
  const alice = await aliceContext.newPage();
  const secondAlice = await secondAliceContext.newPage();
  const bob = await bobContext.newPage();

  await createIdentity(alice, 'alice');
  await alice.getByRole('button', { name: 'Identity' }).click();
  const aliceIdentityLink = await alice.locator('.code-box').innerText();

  await createIdentity(secondAlice, 'alice');
  await secondAlice.getByRole('button', { name: 'Identity' }).click();
  const secondAliceIdentityLink = await secondAlice.locator('.code-box').innerText();

  await createIdentity(bob, 'bob');
  const bobImportPage = await bobContext.newPage();
  await bobImportPage.goto(aliceIdentityLink);
  await expect(bobImportPage.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await bobImportPage.getByLabel('Vault password').fill(password);
  await bobImportPage.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await expect(bobImportPage.locator('.contact-row strong')).toHaveText('alice');

  await bobImportPage.getByRole('button', { name: 'Compose' }).click();
  await expect(bobImportPage.locator('#recipient option', { hasText: 'alice' })).toHaveCount(1);

  await importContact(bobImportPage, secondAliceIdentityLink);
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
