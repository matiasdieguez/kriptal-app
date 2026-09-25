import { test, expect } from '@playwright/test';

const password = 'correct horse battery staple';

async function createIdentity(page, username) {
  await page.goto('/');
  await page.getByLabel('Your username').fill(username);
  await page.getByLabel('Choose a strong password').fill(password);
  await page.getByRole('button', { name: 'Generate my identity' }).click();
  await expect(page.locator('.user strong')).toHaveText(username);
}

test('creates a local identity and unlocks it after reload', async ({ browser }) => {
  const context = await browser.newContext();
  const page = await context.newPage();

  await createIdentity(page, 'maren');
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

  await alice.getByRole('button', { name: 'Contacts' }).click();
  alice.once('dialog', dialog => dialog.accept(bobIdentityLink));
  await alice.getByRole('button', { name: 'Import public key link' }).click();
  await expect(alice.locator('.contact-row strong')).toHaveText('bob');

  await bob.getByRole('button', { name: 'Contacts' }).click();
  bob.once('dialog', dialog => dialog.accept(aliceIdentityLink));
  await bob.getByRole('button', { name: 'Import public key link' }).click();
  await expect(bob.locator('.contact-row strong')).toHaveText('alice');

  await bob.getByRole('button', { name: 'Compose' }).click();
  await bob.locator('#recipient').selectOption({ label: 'alice' });
  await bob.locator('#message').fill('A message only Alice can read.');
  await bob.getByRole('button', { name: 'Encrypt & create link' }).click();
  await expect(bob.locator('.modal')).toBeVisible();
  const messageLink = await bob.locator('.modal .code-box').innerText();
  expect(messageLink).toContain('#m=');

  const incoming = await aliceContext.newPage();
  await incoming.goto(messageLink);
  await expect(incoming).toHaveURL(/#m=/);
  await expect(incoming.getByRole('heading', { name: 'Unlock your vault' })).toBeVisible();
  await incoming.getByLabel('Vault password').fill(password);
  await incoming.getByRole('button', { name: 'Unlock Kriptal' }).click();
  await expect(incoming.getByText('Encrypted link detected.')).toBeVisible();
  await incoming.getByRole('button', { name: 'Verify & decrypt incoming link' }).click();
  await expect(incoming.getByText('Verified from bob')).toBeVisible();
  await expect(incoming.getByText('A message only Alice can read.')).toBeVisible();

  await aliceContext.close();
  await bobContext.close();
});
