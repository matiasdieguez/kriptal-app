import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { b64, bytes, jsonBytes, random, VERSION } from './common.js';

async function passwordKey(password, salt) {
  const material = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptBytes(value, key) {
  const iv = random(12);
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, value);
  return { iv: b64(iv), data: b64(cipher) };
}

export async function decryptBytes(record, key) {
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(record.iv) }, key, bytes(record.data));
}

export async function encryptVault(vault, password) {
  const salt = random(16);
  const key = await passwordKey(password, salt);
  return { version: VERSION, salt: b64(salt), ...(await encryptBytes(jsonBytes(vault), key)) };
}

export async function decryptVault(record, password) {
  const key = await passwordKey(password, bytes(record.salt));
  return JSON.parse(new TextDecoder().decode(await decryptBytes(record, key)));
}

async function importPublic(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

async function importPrivate(jwk) {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits'
  ]);
}

export async function sharedEcdh(privateJwk, publicJwk) {
  return crypto.subtle.deriveBits(
    { name: 'ECDH', public: await importPublic(publicJwk) },
    await importPrivate(privateJwk),
    256
  );
}

export async function hybridKey(ecdhBits, kemSecret, salt) {
  const material = await crypto.subtle.importKey(
    'raw',
    new Uint8Array([...new Uint8Array(ecdhBits), ...kemSecret]),
    'HKDF',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode('Kriptal hybrid ML-KEM-768 + P-256 v2')
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function signKeyData() {
  return ml_dsa65.keygen();
}

export function signPayload(payload, privateKey) {
  return b64(ml_dsa65.sign(jsonBytes(payload), bytes(privateKey)));
}

export function verifyPayload(payload, signature, publicKey) {
  return ml_dsa65.verify(bytes(signature), jsonBytes(payload), bytes(publicKey));
}

export function encapsulate(publicKey) {
  return ml_kem768.encapsulate(bytes(publicKey));
}

export function decapsulate(cipherText, secretKey) {
  return ml_kem768.decapsulate(bytes(cipherText), bytes(secretKey));
}

export async function newIdentity(username) {
  const ecdh = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits'
  ]);
  const signing = signKeyData();
  const kem = ml_kem768.keygen();
  return {
    username,
    publicKey: await crypto.subtle.exportKey('jwk', ecdh.publicKey),
    privateKey: await crypto.subtle.exportKey('jwk', ecdh.privateKey),
    signingPublicKey: b64(signing.publicKey),
    signingPrivateKey: b64(signing.secretKey),
    kemPublicKey: b64(kem.publicKey),
    kemSecretKey: b64(kem.secretKey),
    contacts: []
  };
}

export async function publicFingerprint(contact) {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    jsonBytes({
      ecdh: contact.publicKey,
      kem: contact.kemPublicKey,
      signing: contact.signingPublicKey
    })
  );
  return b64(digest)
    .slice(0, 20)
    .match(/.{1,4}/g)
    .join(' ');
}
