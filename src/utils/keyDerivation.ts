import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { bech32 } from 'bech32';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
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

const HARDENED_OFFSET = 0x80000000;

// BIP85 application numbers
const BIP85_APPLICATIONS = {
  BIP39: 39,
  BIP39_WORD_COUNT: 12,
  BIP39_LANGUAGE: 0,
} as const;

const toHardened = (index: number): number => index + HARDENED_OFFSET;

const formatHardenedPath = (index: number): string => 
  index >= HARDENED_OFFSET ? `${index - HARDENED_OFFSET}'` : index.toString();

const constructBip85Path = (index: number): string => {
  return `m/83696968'/${BIP85_APPLICATIONS.BIP39}'/${BIP85_APPLICATIONS.BIP39_WORD_COUNT}'/${BIP85_APPLICATIONS.BIP39_LANGUAGE}'/${index}'`;
};

const deriveBip85Entropy = (masterKey: HDKey, index: number): Uint8Array => {
  const path = constructBip85Path(index);
  const derived = masterKey.derive(path);
  if (!derived.privateKey) throw new Error('Unable to derive private key');
  return derived.privateKey;
};

const base58Encode = (data: Uint8Array): string => {
  const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt(0);
  for (const byte of data) {
    num = num * BigInt(256) + BigInt(byte);
  }
  let encoded = '';
  while (num > BigInt(0)) {
    encoded = BASE58_ALPHABET[Number(num % BigInt(58))] + encoded;
    num = num / BigInt(58);
  }
  // Add leading zeros
  for (let i = 0; i < data.length && data[i] === 0; i++) {
    encoded = '1' + encoded;
  }
  return encoded;
};

export const deriveCurrentMnemonic = (rootSeedPhrase: string, path: number[]): string => {
  if (path.length === 0) return rootSeedPhrase;
  
  if (!bip39.validateMnemonic(rootSeedPhrase, wordlist)) {
    throw new Error('Invalid root seed phrase');
  }
  
  const seed = bip39.mnemonicToSeedSync(rootSeedPhrase);
  const masterKey = HDKey.fromMasterSeed(seed);
  
  let currentEntropy = deriveBip85Entropy(masterKey, path[0]);
  
  for (let i = 1; i < path.length; i++) {
    const intermediateKey = HDKey.fromMasterSeed(currentEntropy);
    currentEntropy = deriveBip85Entropy(intermediateKey, path[i]);
  }
  
  return bip39.entropyToMnemonic(currentEntropy, wordlist);
};

const privateKeyToWIF = (privateKey: Uint8Array): string => {
  // Version byte for mainnet private key (0x80)
  const versionByte = new Uint8Array([0x80]);
  // Compression byte (0x01)
  const compressionByte = new Uint8Array([0x01]);
  
  // Concatenate version byte + private key + compression byte
  const combined = new Uint8Array(versionByte.length + privateKey.length + compressionByte.length);
  combined.set(versionByte);
  combined.set(privateKey, versionByte.length);
  combined.set(compressionByte, versionByte.length + privateKey.length);
  
  // Double SHA256
  const firstHash = sha256(combined);
  const secondHash = sha256(firstHash);
  
  // First 4 bytes of double-SHA256 as checksum
  const checksum = secondHash.slice(0, 4);
  
  // Final: version + private key + compression byte + checksum
  const final = new Uint8Array(combined.length + checksum.length);
  final.set(combined);
  final.set(checksum, combined.length);
  
  // Encode in base58
  return base58Encode(final);
};

export const deriveBitcoinKeys = (masterKey: HDKey, path: string): BitcoinKeys => {
  const key = masterKey.derive(path);
  if (!key.privateKey || !key.publicKey) throw new Error('Keys not available');

  const sha256Hash = sha256(sha256(key.publicKey));
  const pubkeyHash = ripemd160(sha256Hash);

  // Create witness program: [version (0x00), pubkeyHash]
  const witnessProgram = new Uint8Array([0x00, ...pubkeyHash]);
  return {
    address: bech32.encode('bc', bech32.toWords(witnessProgram)),
    privateKeyWIF: privateKeyToWIF(key.privateKey),
  };
};

export const deriveNostrKeys = (masterKey: HDKey, path: string): NostrKeys => {
  const key = masterKey.derive(path);
  if (!key.privateKey || !key.publicKey) throw new Error('Keys not available');
  
  return {
    nsec: bech32.encode('nsec', bech32.toWords(key.privateKey)),
    npub: bech32.encode('npub', bech32.toWords(key.publicKey)),
  };
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