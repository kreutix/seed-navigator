import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { bech32, bech32m } from 'bech32';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex } from '@noble/hashes/utils';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmac } from '@noble/hashes/hmac';

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
  BIP39_LANGUAGES: {
    ENGLISH: 0,
    JAPANESE: 1,
    KOREAN: 2,
    SPANISH: 3,
    CHINESE_SIMPLIFIED: 4,
    CHINESE_TRADITIONAL: 5,
    FRENCH: 6,
    ITALIAN: 7,
    CZECH: 8,
    PORTUGUESE: 9
  },
  BIP39_WORD_LENGTHS: {
    WORDS_12: { words: 12, bits: 128 },
    WORDS_15: { words: 15, bits: 160 },
    WORDS_18: { words: 18, bits: 192 },
    WORDS_21: { words: 21, bits: 224 },
    WORDS_24: { words: 24, bits: 256 }
  }
} as const;

const toHardened = (index: number): number => index + HARDENED_OFFSET;

const formatHardenedPath = (index: number): string => 
  index >= HARDENED_OFFSET ? `${index - HARDENED_OFFSET}'` : index.toString();

const validateBip85Params = (index: number, language: number, words: number) => {
  if (index < 0 || index >= 0x80000000) {
    throw new Error('Invalid index: must be between 0 and 2147483647');
  }
  if (language < 0 || language > 9) {
    throw new Error('Invalid language code');
  }
  if (![12, 15, 18, 21, 24].includes(words)) {
    throw new Error('Invalid word count: must be 12, 15, 18, 21, or 24');
  }
};

const constructBip85Path = (index: number, language: number = 0, words: number = 12): string => {
  validateBip85Params(index, language, words);
  // BIP-85 paths are always hardened, so we use the ' notation
  return `m/83696968'/${BIP85_APPLICATIONS.BIP39}'/${language}'/${words}'/${index}'`;
};

const deriveBip85Entropy = (masterKey: HDKey, index: number, language: number = 0, words: number = 12): Uint8Array => {
  const path = constructBip85Path(index, language, words);
  const derived = masterKey.derive(path);
  if (!derived.privateKey) throw new Error('Unable to derive private key');
  
  // As per BIP-85: HMAC-SHA512(key="bip-entropy-from-k", msg=k)
  const hmacKey = new TextEncoder().encode("bip-entropy-from-k");
  const fullEntropy = hmac.create(sha512, hmacKey).update(derived.privateKey).digest();
  
  // Return the appropriate number of bits based on word count
  const bits = BIP85_APPLICATIONS.BIP39_WORD_LENGTHS[`WORDS_${words}` as keyof typeof BIP85_APPLICATIONS.BIP39_WORD_LENGTHS].bits;
  return fullEntropy.slice(0, bits / 8);
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
  
  // Using English 24-word mnemonics
  const language = BIP85_APPLICATIONS.BIP39_LANGUAGES.ENGLISH;
  const words = BIP85_APPLICATIONS.BIP39_WORD_LENGTHS.WORDS_24.words;
  
  const entropy = deriveBip85Entropy(masterKey, path[0], language, words);
  return bip39.entropyToMnemonic(entropy, wordlist);
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
  const pubkeyHash = ripemd160(sha256(key.publicKey));
  let witnessProgram = '';
  let checksum = '';

  if (path.startsWith("m/84'/")) { // Native SegWit (P2WPKH)
    // For P2WPKH, witness version 0 and push 20 bytes
    const words = bech32.toWords(pubkeyHash);
    // Prepend witness version 0
    const fullWords = new Uint8Array([0, ...words]);
    // Encode with bech32
    address = bech32.encode('bc', fullWords);
    // For witnessProgram display, show the full script including OP_0 OP_PUSHBYTES_20
    witnessProgram = '0014' + bytesToHex(pubkeyHash);
  } 
  else if (path.startsWith("m/49'/")) { // Nested SegWit (P2SH-P2WPKH)
    // Create redeem script (OP_0 + OP_PUSHBYTES_20 + <pubKeyHash>)
    const redeemScript = new Uint8Array([0x00, 0x14, ...pubkeyHash]);
    // Hash160 of the redeem script
    const scriptHash = ripemd160(sha256(redeemScript));
    // P2SH version byte (0x05) + scriptHash + checksum
    const versionAndHash = new Uint8Array([0x05, ...scriptHash]);
    const checksumBytes = sha256(sha256(versionAndHash)).slice(0, 4);
    const final = new Uint8Array([...versionAndHash, ...checksumBytes]);
    address = base58Encode(final);
    // Store the redeem script for display
    witnessProgram = bytesToHex(redeemScript);
    checksum = bytesToHex(checksumBytes);
  }
  else if (path.startsWith("m/86'/")) { // Taproot (P2TR)
    // For Taproot, we need to use the x-only public key (32 bytes)
    // Just take the 32 bytes x-coordinate from the 33-byte compressed public key
    // Removing the first byte (0x02 or 0x03) which indicates parity
    const xOnlyPubKey = key.publicKey.slice(1);
    // For P2TR, witness version 1 and push 32 bytes
    const words = bech32m.toWords(xOnlyPubKey);
    // Prepend witness version 1
    const fullWords = new Uint8Array([1, ...words]);
    // Encode with bech32m (not regular bech32)
    address = bech32m.encode('bc', fullWords);
    // For witnessProgram display, show the full script including OP_1 OP_PUSHBYTES_32
    witnessProgram = '5120' + bytesToHex(xOnlyPubKey);
  }
  else if (path.startsWith("m/44'/")) { // Legacy (P2PKH)
    // P2PKH version byte (0x00) + pubkeyHash + checksum
    const versionAndHash = new Uint8Array([0x00, ...pubkeyHash]);
    const checksumBytes = sha256(sha256(versionAndHash)).slice(0, 4);
    const final = new Uint8Array([...versionAndHash, ...checksumBytes]);
    address = base58Encode(final);
    checksum = bytesToHex(checksumBytes);
  } 
  else {
    throw new Error('Unsupported derivation path for Bitcoin');
  }

  return {
    address,
    privateKeyWIF: privateKeyToWIF(key.privateKey),
    publicKey: publicKeyHex,
    publicKeyHash,
    publicKeyHash160,
    witnessProgram,
    checksum
  };
};

export const deriveNostrKeys = (masterKey: HDKey, path: string): NostrKeys => {
  const key = masterKey.derive(path);
  if (!key.privateKey || !key.publicKey) throw new Error('Keys not available');
  
  // For Nostr, we need to ensure we're using the 32-byte private key
  // and the correct compressed public key format
  return {
    nsec: bech32.encode('nsec', bech32.toWords(key.privateKey)),
    npub: bech32.encode('npub', bech32.toWords(key.publicKey.slice(1))), // Use x-only pubkey for Nostr
  };
};

export type PathType = 'bitcoin' | 'nostr' | 'unknown';

export const getPathType = (path: string): PathType => {
  // Bitcoin paths
  if (path.startsWith("m/44'/0'/") || // Legacy (P2PKH)
      path.startsWith("m/49'/0'/") || // Nested SegWit (P2SH-P2WPKH)
      path.startsWith("m/84'/0'/") || // Native SegWit (P2WPKH)
      path.startsWith("m/86'/0'/")) { // Taproot (P2TR)
    return 'bitcoin';
  }
  
  // Nostr paths
  if (path.startsWith("m/44'/1237'/")) {
    return 'nostr';
  }

  return 'unknown';
};

// Add test function to verify implementation
export const testBip85Implementation = () => {
  const testMasterKey = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
  const masterKey = HDKey.fromExtendedKey(testMasterKey);
  
  // Test case 1: 12 words
  const entropy1 = deriveBip85Entropy(masterKey, 0);
  const expectedEntropy1 = "6250b68daf746d12a24d58b4787a714b";
  const derivedEntropy1 = bytesToHex(entropy1);
  const expectedMnemonic1 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose";
  const derivedMnemonic1 = bip39.entropyToMnemonic(entropy1, wordlist);
  
  if (derivedEntropy1 !== expectedEntropy1) {
    throw new Error(`BIP-85 test case 1 entropy verification failed:
      Expected: ${expectedEntropy1}
      Got: ${derivedEntropy1}`);
  }
  
  if (derivedMnemonic1 !== expectedMnemonic1) {
    throw new Error(`BIP-85 test case 1 mnemonic verification failed:
      Expected: ${expectedMnemonic1}
      Got: ${derivedMnemonic1}`);
  }
  
  // Test case 2: 24 words
  const entropy2 = deriveBip85Entropy(masterKey, 0, 0, 24);
  const expectedEntropy2 = "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f";
  const derivedEntropy2 = bytesToHex(entropy2);
  const expectedMnemonic2 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano";
  const derivedMnemonic2 = bip39.entropyToMnemonic(entropy2, wordlist);
  
  if (derivedEntropy2 !== expectedEntropy2) {
    throw new Error(`BIP-85 test case 2 entropy verification failed:
      Expected: ${expectedEntropy2}
      Got: ${derivedEntropy2}`);
  }
  
  if (derivedMnemonic2 !== expectedMnemonic2) {
    throw new Error(`BIP-85 test case 2 mnemonic verification failed:
      Expected: ${expectedMnemonic2}
      Got: ${derivedMnemonic2}`);
  }
  
  return true;
}; 
