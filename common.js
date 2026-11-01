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
    if (value.startsWith('m2.')) return decodeMessagePayload(decodeBase85(value.slice(3)));
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

export function encodeMessagePayload(value) {
  const sender = [bytes(value.senderKey.x), bytes(value.senderKey.y)];
  const recipient = [bytes(value.recipientKey.x), bytes(value.recipientKey.y)];
  const ephemeral = [bytes(value.ephemeralKey.x), bytes(value.ephemeralKey.y)];
  const from = textEncoder.encode(value.from);
  const id = bytes(value.id);
  const signingKey = bytes(value.signingKey);
  const kemCipherText = bytes(value.kemCipherText);
  const salt = bytes(value.salt);
  const iv = bytes(value.iv);
  const data = bytes(value.data);
  const signature = bytes(value.signature);
  const size =
    13 +
    2 + from.length +
    id.length +
    sender[0].length + sender[1].length +
    4 + signingKey.length +
    recipient[0].length + recipient[1].length +
    ephemeral[0].length + ephemeral[1].length +
    [kemCipherText, salt, iv, data, signature].reduce(
      (total, field) => total + 4 + field.length,
      0
    );
  const payload = new Uint8Array(size);
  const view = new DataView(payload.buffer);
  payload[0] = value.v;
  view.setUint32(1, size);
  view.setFloat64(5, value.created);
  let offset = 13;
  view.setUint16(offset, from.length);
  offset += 2;
  payload.set(from, offset);
  offset += from.length;
  for (const field of [id, ...sender]) {
    payload.set(field, offset);
    offset += field.length;
  }
  for (const field of [signingKey]) {
    view.setUint32(offset, field.length);
    offset += 4;
    payload.set(field, offset);
    offset += field.length;
  }
  for (const field of [...recipient, ...ephemeral]) {
    payload.set(field, offset);
    offset += field.length;
  }
  for (const field of [kemCipherText, salt, iv, data, signature]) {
    view.setUint32(offset, field.length);
    offset += 4;
    payload.set(field, offset);
    offset += field.length;
  }
  return `m2.${encodeBase85(payload)}`;
}

function decodeMessagePayload(payload) {
  if (payload.length < 13) throw new Error('Malformed message link');
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const version = payload[0];
  const payloadLength = view.getUint32(1);
  if (payloadLength < 13 || payloadLength > payload.length)
    throw new Error('Malformed message link');
  const created = view.getFloat64(5);
  payload = payload.subarray(0, payloadLength);
  let offset = 13;

  function readField(fixedLength = null) {
    const length = fixedLength ?? new DataView(
      payload.buffer,
      payload.byteOffset + offset,
      4
    ).getUint32(0);
    if (fixedLength === null) offset += 4;
    if (offset + length > payload.length) throw new Error('Malformed message link');
    const field = payload.slice(offset, offset + length);
    offset += length;
    return field;
  }

  if (offset + 2 > payload.length) throw new Error('Malformed message link');
  const fromLength = new DataView(
    payload.buffer,
    payload.byteOffset + offset,
    2
  ).getUint16(0);
  offset += 2;
  const from = textDecoder.decode(readField(fromLength));
  const id = readField(16);
  const senderX = readField(32);
  const senderY = readField(32);
  const signingKey = readField(null);
  const recipientX = readField(32);
  const recipientY = readField(32);
  const ephemeralX = readField(32);
  const ephemeralY = readField(32);
  const kemCipherText = readField(null);
  const salt = readField(null);
  const iv = readField(null);
  const data = readField(null);
  const signature = readField(null);
  if (offset !== payload.length) throw new Error('Malformed message link');

  function jwk(x, y) {
    return {
      crv: 'P-256',
      ext: true,
      key_ops: [],
      kty: 'EC',
      x: b64(x),
      y: b64(y)
    };
  }

  return {
    v: version,
    id: b64(id),
    created,
    from,
    senderKey: jwk(senderX, senderY),
    signingKey: b64(signingKey),
    recipientKey: jwk(recipientX, recipientY),
    ephemeralKey: jwk(ephemeralX, ephemeralY),
    kemCipherText: b64(kemCipherText),
    salt: b64(salt),
    iv: b64(iv),
    data: b64(data),
    signature: b64(signature)
  };
}

export function linkFor(type, value) {
  const encoded =
    type === 'k'
      ? encodeIdentityPayload(value)
      : type === 'm'
        ? encodeMessagePayload(value)
        : encodePayload(value);
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
