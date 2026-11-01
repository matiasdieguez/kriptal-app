export const VAULT_KEY = 'kriptal.vault';
export const REPLAY_KEY = 'kriptal.replayed';
export const VERSION = 2;
export const MAX_MESSAGE_BYTES = 10000;
export const MAX_FILE_BYTES = 50 * 1024;
export const MAX_LINK_LENGTH = 180000;
export const MAX_MESSAGE_AGE = 7 * 24 * 60 * 60 * 1000;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const base85Alphabet =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!$'()*,-./:;?@[]^_`{|}~";

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
    if (value.startsWith('id2.')) return decodeIdentityPayload(decodeBase85(value.slice(4)));
    return fromJson(bytes(value));
  } catch {
    return null;
  }
}

export function encodeIdentityPayload(value) {
  const username = textEncoder.encode(value.username);
  const fields = [
    bytes(value.publicKey.x),
    bytes(value.publicKey.y),
    bytes(value.kemPublicKey),
    bytes(value.signingPublicKey)
  ];
  const size = 5 + username.length + fields.reduce((total, field) => total + 2 + field.length, 0);
  const payload = new Uint8Array(size);
  const view = new DataView(payload.buffer);
  let offset = 0;
  payload[offset++] = VERSION;
  view.setUint16(offset, payload.length);
  offset += 2;
  view.setUint16(offset, username.length);
  offset += 2;
  payload.set(username, offset);
  offset += username.length;
  for (const field of fields) {
    view.setUint16(offset, field.length);
    offset += 2;
    payload.set(field, offset);
    offset += field.length;
  }
  return `id2.${encodeBase85(payload)}`;
}

function decodeIdentityPayload(payload) {
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let offset = 0;
  if (payload[offset++] !== VERSION) throw new Error('Unsupported identity link version');
  const payloadLength = view.getUint16(offset);
  offset += 2;
  if (payloadLength < 5 || payloadLength > payload.length) throw new Error('Malformed identity link');
  payload = payload.subarray(0, payloadLength);
  const usernameLength = view.getUint16(offset);
  offset += 2;
  const username = textDecoder.decode(payload.subarray(offset, offset + usernameLength));
  offset += usernameLength;
  const fields = [];
  for (let i = 0; i < 4; i++) {
    const length = view.getUint16(offset);
    offset += 2;
    fields.push(payload.slice(offset, offset + length));
    offset += length;
  }
  if (offset !== payload.length) throw new Error('Malformed identity link');
  return {
    v: VERSION,
    username,
    publicKey: {
      crv: 'P-256',
      ext: true,
      key_ops: [],
      kty: 'EC',
      x: b64(fields[0]),
      y: b64(fields[1])
    },
    kemPublicKey: b64(fields[2]),
    signingPublicKey: b64(fields[3])
  };
}

function encodeBase85(value) {
  let encoded = '';
  for (let offset = 0; offset < value.length; offset += 4) {
    let block = 0;
    for (let i = 0; i < 4; i++)
      block = block * 256 + (value[offset + i] || 0);
    const digits = new Array(5);
    for (let i = 4; i >= 0; i--) {
      digits[i] = base85Alphabet[block % 85];
      block = Math.floor(block / 85);
    }
    encoded += digits.join('');
  }
  return encoded;
}

function decodeBase85(value) {
  if (value.length % 5 !== 0) throw new Error('Malformed identity link');
  const decoded = new Uint8Array((value.length / 5) * 4);
  for (let offset = 0; offset < value.length; offset += 5) {
    let block = 0;
    for (let i = 0; i < 5; i++) {
      const digit = base85Alphabet.indexOf(value[offset + i]);
      if (digit < 0) throw new Error('Malformed identity link');
      block = block * 85 + digit;
    }
    if (block > 0xffffffff) throw new Error('Malformed identity link');
    const byteOffset = (offset / 5) * 4;
    for (let i = 3; i >= 0; i--) {
      decoded[byteOffset + i] = block % 256;
      block = Math.floor(block / 256);
    }
  }
  return decoded;
}

export function linkFor(type, value) {
  const encoded = type === 'k' ? encodeIdentityPayload(value) : encodePayload(value);
  return `${location.origin}${location.pathname}#${type}=${encoded}`;
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
