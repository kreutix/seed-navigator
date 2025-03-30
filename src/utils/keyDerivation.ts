import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32 } from 'bech32';
import { sha256 } from 'js-sha256';
import { wordlist } from '@scure/bip39/wordlists/english';

export interface NostrKeys {
  nsec: string;
  npub: string;
}

export interface BitcoinKeys {
  address: string;
  privateKeyWIF: string;
}

export interface DerivedKeys {
  index: number;
  nsec: string;
  npub: string;
  bitcoinAddress: string;
  bitcoinPrivateKey: string;
}

// BIP85 application numbers
const BIP85_APPLICATIONS = {
  BIP39: 39,
  XPRV: 32,
} as const;

// Constants for BIP39
const WORD_COUNT = 24; // Always use 24 words
const ENTROPY_BYTES = 32; // 256 bits = 32 bytes for 24 words

// Convert number to 32-bit big-endian bytes
const indexToBytes = (index: number): Uint8Array => {
  const bytes = new Uint8Array(4);
  bytes[0] = (index >> 24) & 0xff;
  bytes[1] = (index >> 16) & 0xff;
  bytes[2] = (index >> 8) & 0xff;
  bytes[3] = index & 0xff;
  return bytes;
};

// Derive BIP85 child entropy
const deriveBip85Entropy = (masterKey: HDKey, path: string): Uint8Array => {
  const childKey = masterKey.derive(path);
  if (!childKey.privateKey) throw new Error('Could not derive private key');
  return new Uint8Array(childKey.privateKey);
};

// Derive BIP39 mnemonic using BIP85
const deriveBip85Mnemonic = (masterKey: HDKey, index: number): string => {
  // BIP85 path: m/83696968'/39'/0'/24'/index' (always use 24 words)
  const path = `m/83696968'/${BIP85_APPLICATIONS.BIP39}'/0'/${WORD_COUNT}'/${index}'`;
  const entropy = deriveBip85Entropy(masterKey, path);
  
  // Use full 32 bytes of entropy for 24 words
  return bip39.entropyToMnemonic(entropy, wordlist);
};

// Validate that a mnemonic is 24 words
const validateMnemonic = (mnemonic: string): boolean => {
  if (!bip39.validateMnemonic(mnemonic, wordlist)) return false;
  const words = mnemonic.trim().split(/\s+/);
  return words.length === WORD_COUNT;
};

const arrayBufferToUint8Array = (buffer: ArrayBuffer): Uint8Array => {
  return new Uint8Array(buffer);
};

const privateKeyToWIF = (privateKey: Uint8Array): string => {
  const extendedKey = new Uint8Array(34);
  extendedKey[0] = 0x80; // Mainnet private key prefix
  extendedKey.set(privateKey, 1);
  extendedKey[33] = 0x01; // Compressed pubkey flag

  const firstSha = arrayBufferToUint8Array(sha256.arrayBuffer(extendedKey));
  const secondSha = arrayBufferToUint8Array(sha256.arrayBuffer(firstSha));

  const finalKey = new Uint8Array(38);
  finalKey.set(extendedKey);
  finalKey.set(secondSha.slice(0, 4), 34); // Checksum

  const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt(0);
  for (let i = 0; i < finalKey.length; i++) {
    num = num * BigInt(256) + BigInt(finalKey[i]);
  }

  let wif = '';
  while (num > BigInt(0)) {
    const mod = num % BigInt(58);
    wif = BASE58_CHARS[Number(mod)] + wif;
    num = num / BigInt(58);
  }

  // Add leading 1's for zero bytes
  for (let i = 0; i < finalKey.length && finalKey[i] === 0; i++) {
    wif = '1' + wif;
  }

  return wif;
};

export const deriveNostrKeys = (hdKey: HDKey): NostrKeys => {
  if (!hdKey.privateKey || !hdKey.publicKey) {
    throw new Error('Keys not available in the HDKey');
  }

  const privateKeyWords = bech32.toWords(hdKey.privateKey);
  const publicKeyWords = bech32.toWords(hdKey.publicKey);

  return {
    nsec: bech32.encode('nsec', privateKeyWords),
    npub: bech32.encode('npub', publicKeyWords),
  };
};

export const deriveBitcoinKeys = (hdKey: HDKey, path: string): BitcoinKeys => {
  const derivedKey = hdKey.derive(path);
  if (!derivedKey.publicKey || !derivedKey.privateKey) {
    throw new Error('Keys not available');
  }

  // SHA256 + RIPEMD160 (hash160) of the public key
  const sha256HashArray = arrayBufferToUint8Array(sha256.arrayBuffer(derivedKey.publicKey));
  const ripemd160Hash = sha256HashArray.slice(0, 20); // TODO: Implement proper RIPEMD160

  // Create witness program (version 0 + pubkey hash)
  const witnessProgram = new Uint8Array(ripemd160Hash.length + 1);
  witnessProgram[0] = 0x00; // Version 0 witness program
  witnessProgram.set(ripemd160Hash, 1);

  return {
    address: bech32.encode('bc', bech32.toWords(witnessProgram)),
    privateKeyWIF: privateKeyToWIF(derivedKey.privateKey),
  };
};

export const deriveCurrentMnemonic = (rootMnemonic: string, path: number[]): string => {
  // Validate that root mnemonic is 24 words
  if (!validateMnemonic(rootMnemonic)) {
    throw new Error('Root mnemonic must be 24 words');
  }

  const seed = bip39.mnemonicToSeedSync(rootMnemonic);
  const masterKey = HDKey.fromMasterSeed(seed);
  
  if (path.length === 0) {
    return rootMnemonic;
  }

  // Use BIP85 to derive child mnemonic (always 24 words)
  const lastIndex = path[path.length - 1];
  return deriveBip85Mnemonic(masterKey, lastIndex);
};

export type PathType = 'bitcoin' | 'nostr' | 'unknown';

export const getPathType = (path: string): PathType => {
  // Bitcoin paths
  if (path.startsWith("m/44'/0'/") || // Legacy
      path.startsWith("m/49'/0'/") || // Nested SegWit
      path.startsWith("m/84'/0'/") || // Native SegWit
      path.startsWith("m/86'/0'/")) { // Taproot
    return 'bitcoin';
  }
  
  // Nostr paths
  if (path.startsWith("m/44'/1237'/")) {
    return 'nostr';
  }

  return 'unknown';
}; 