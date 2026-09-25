export const VAULT_KEY = 'kriptal.vault';
export const REPLAY_KEY = 'kriptal.replayed';
export const VERSION = 2;
export const MAX_MESSAGE_BYTES = 10000;
export const MAX_FILE_BYTES = 50 * 1024;
export const MAX_LINK_LENGTH = 180000;
export const MAX_MESSAGE_AGE = 7 * 24 * 60 * 60 * 1000;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const qrParts = new Map();

export const b64 = (value) =>
  btoa(String.fromCharCode(...new Uint8Array(value)))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');

export const bytes = (value) =>
  Uint8Array.from(
    atob(
      value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4)
    ),
    (char) => char.charCodeAt(0)
  );

export const jsonBytes = (value) => textEncoder.encode(JSON.stringify(value));
export const fromJson = (value) => JSON.parse(textDecoder.decode(value));
export const random = (length) => crypto.getRandomValues(new Uint8Array(length));
export const escapeHtml = (value) =>
  String(value).replace(
    /[&<>'"]/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[char]
  );

export function readRoute(type) {
  const value = new URLSearchParams(location.hash.slice(1)).get(type);
  return value && value.length <= MAX_LINK_LENGTH ? decodePayload(value) : null;
}

export function encodePayload(value) {
  return b64(jsonBytes(value));
}

export function decodePayload(value) {
  try {
    return fromJson(bytes(value));
  } catch {
    return null;
  }
}

export function linkFor(type, value) {
  return `${location.origin}${location.pathname}#${type}=${encodePayload(value)}`;
}

export function qrPartsFor(value) {
  const encoded = encodePayload(value);
  const chunkSize = 1500;
  const id = b64(random(6));
  const chunks = [];
  for (let offset = 0; offset < encoded.length; offset += chunkSize)
    chunks.push(encoded.slice(offset, offset + chunkSize));
  return chunks.map((chunk, index) => `kr2.${id}.${index + 1}.${chunks.length}.${chunk}`);
}

export function readQrData(data) {
  if (!data.startsWith('kr2.')) return data;
  const [, id, indexText, totalText, chunk] = data.split('.');
  const index = Number(indexText);
  const total = Number(totalText);
  if (
    !id ||
    !Number.isInteger(index) ||
    !Number.isInteger(total) ||
    index < 1 ||
    index > total ||
    !chunk ||
    total > 20
  )
    return null;
  const parts = qrParts.get(id) || { total, chunks: new Array(total) };
  if (parts.total !== total) return null;
  parts.chunks[index - 1] = chunk;
  qrParts.set(id, parts);
  if (parts.chunks.some((part) => !part))
    return { pending: true, received: parts.chunks.filter(Boolean).length, total };
  qrParts.delete(id);
  return decodePayload(parts.chunks.join(''));
}

export function storeRecord(record) {
  localStorage.setItem(VAULT_KEY, JSON.stringify(record));
}

export function storedRecord() {
  try {
    return JSON.parse(localStorage.getItem(VAULT_KEY));
  } catch {
    return null;
  }
}

export function replayedIds() {
  try {
    return JSON.parse(localStorage.getItem(REPLAY_KEY) || '[]');
  } catch {
    return [];
  }
}

export function isReplayed(id) {
  return replayedIds().includes(id);
}

export function markReplayed(id) {
  localStorage.setItem(REPLAY_KEY, JSON.stringify([...replayedIds().slice(-99), id]));
}

export function validMessage(payload) {
  return (
    payload?.v === VERSION &&
    typeof payload.id === 'string' &&
    typeof payload.created === 'number' &&
    Date.now() - payload.created <= MAX_MESSAGE_AGE &&
    Date.now() - payload.created >= -60000 &&
    typeof payload.senderKey === 'object' &&
    typeof payload.signingKey === 'string' &&
    typeof payload.ephemeralKey === 'object' &&
    typeof payload.kemCipherText === 'string' &&
    typeof payload.salt === 'string' &&
    typeof payload.iv === 'string' &&
    typeof payload.data === 'string'
  );
}

export function validContact(payload) {
  return (
    payload?.v === VERSION &&
    typeof payload.username === 'string' &&
    payload.publicKey &&
    payload.kemPublicKey &&
    payload.signingPublicKey
  );
}
