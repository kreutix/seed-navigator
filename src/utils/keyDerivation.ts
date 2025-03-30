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
  publicKey: string;
  publicKeyHash: string;
  publicKeyHash160: string;
  witnessProgram: string;
  checksum: string;
}

export interface DerivedKeys {
  index: number;
  nsec: string;
  npub: string;
  bitcoinAddress: string;
  bitcoinPrivateKey: string;
  bitcoinPublicKey: string;
  bitcoinPublicKeyHash: string;
  bitcoinPublicKeyHash160: string;
  bitcoinWitnessProgram: string;
  bitcoinChecksum: string;
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

  const pathType = getPathType(path);
  let address: string;
  const publicKeyHex = bytesToHex(key.publicKey);
  const publicKeyHash = bytesToHex(sha256(key.publicKey));
  const publicKeyHash160 = bytesToHex(ripemd160(sha256(key.publicKey)));

  if (path.startsWith("m/84'/")) { // Native SegWit (P2WPKH)
    const pubkeyHash = ripemd160(sha256(key.publicKey));
    // For P2WPKH, witness version 0 and push 20 bytes
    const witnessVersion = 0;
    const programBytes = Uint8Array.from([...pubkeyHash]);
    // Convert to 5-bit words for bech32
    const words = bech32.toWords(programBytes);
    // Add witness version to words
    const witnessProgram = Uint8Array.from([witnessVersion, ...words]);
    // Encode with bech32
    address = bech32.encode('bc', witnessProgram);
  } else if (path.startsWith("m/44'/")) { // Legacy (P2PKH)
    const pubkeyHash = ripemd160(sha256(key.publicKey));
    const versionAndHash = new Uint8Array([0x00, ...pubkeyHash]);
    const checksum = sha256(sha256(versionAndHash)).slice(0, 4);
    const final = new Uint8Array([...versionAndHash, ...checksum]);
    address = base58Encode(final);
  } else {
    throw new Error('Unsupported derivation path for Bitcoin');
  }

  const pubkeyHash = ripemd160(sha256(key.publicKey));
  // For witnessProgram display, show the full script including OP_PUSHBYTES_20
  const scriptPubKey = new Uint8Array([0x00, 0x14, ...pubkeyHash]);
  const witnessProgramWithChecksum = path.startsWith("m/84'/") 
    ? bytesToHex(scriptPubKey)
    : '';

  return {
    address,
    privateKeyWIF: privateKeyToWIF(key.privateKey),
    publicKey: publicKeyHex,
    publicKeyHash,
    publicKeyHash160,
    witnessProgram: witnessProgramWithChecksum,
    checksum: path.startsWith("m/44'/") ? bytesToHex(sha256(sha256(new Uint8Array([0x00, ...pubkeyHash]))).slice(0, 4)) : ''
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