import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { bech32, bech32m } from 'bech32';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { hmac } from '@noble/hashes/hmac';
import { z } from 'zod';

import {
  AppError,
  ErrorType,
  SecureData,
  BIP85_APPLICATIONS,
  mnemonicSchema,
  derivationPathSchema,
  bip85ParamsSchema
} from '../types';
import {
  HARDENED_OFFSET,
  BITCOIN_NETWORK,
  BIP85
} from '../constants/derivationPaths';

// ==============================
// Error Handling Utilities
// ==============================

/**
 * Creates a typed application error
 * @param message - Error message
 * @param type - Error type from ErrorType enum
 * @param details - Additional error details
 * @returns Typed AppError
 */
export function createError(message: string, type: ErrorType, details?: unknown): AppError {
  const error = new Error(message) as AppError;
  error.type = type;
  error.details = details;
  return error;
}

/**
 * Safely executes a function and wraps any errors in a typed AppError
 * @param fn - Function to execute
 * @param errorType - Type of error to create if the function throws
 * @param errorMessage - Message to use for the error
 * @returns Result of the function
 * @throws AppError with the specified type and message
 */
export function safeExec<T>(
  fn: () => T,
  errorType: ErrorType,
  errorMessage: string
): T {
  try {
    return fn();
  } catch (error) {
    throw createError(
      errorMessage,
      errorType,
      error instanceof Error ? error.message : String(error)
    );
  }
}

// ==============================
// Secure Memory Handling
// ==============================

/**
 * Creates a secure Uint8Array that can be explicitly cleared from memory
 * @param data - Initial data or size for the array
 * @returns SecureData object with the array and a clear method
 */
export function createSecureArray(data: Uint8Array | number): SecureData & { data: Uint8Array } {
  let array: Uint8Array;
  
  if (typeof data === 'number') {
    array = new Uint8Array(data);
  } else {
    array = new Uint8Array(data);
  }
  
  return {
    data: array,
    clear: () => {
      // Overwrite with zeros to remove sensitive data from memory
      array.fill(0);
    }
  };
}

/**
 * Creates a secure string that can be explicitly cleared from memory
 * @param value - Initial string value
 * @returns SecureData object with the string and a clear method
 */
export function createSecureString(value: string): SecureData & { value: string } {
  let secureValue = value;
  
  return {
    get value() { return secureValue; },
    set value(newValue: string) { secureValue = newValue; },
    clear: () => {
      // Overwrite with empty string to help garbage collection
      secureValue = '';
    }
  };
}

/**
 * Securely wipes an HDKey instance from memory
 * @param key - HDKey to wipe
 */
export function clearHDKey(key: HDKey): void {
  if (key.privateKey) {
    // Overwrite private key with zeros
    key.privateKey.fill(0);
  }
  
  // Set properties to undefined to help garbage collection
  // @ts-ignore - Intentionally clearing internal properties
  key.privateKey = undefined;
  // @ts-ignore - Intentionally clearing internal properties
  key.publicKey = undefined;
  // @ts-ignore - Intentionally clearing internal properties
  key.chainCode = undefined;
}

// ==============================
// Base Encoding/Decoding Functions
// ==============================

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encodes data as Base58
 * @param data - Bytes to encode
 * @returns Base58 encoded string
 */
export function base58Encode(data: Uint8Array): string {
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
}

/**
 * Decodes a Base58 string to bytes
 * @param encoded - Base58 encoded string
 * @returns Decoded bytes
 * @throws Error if the input contains invalid characters
 */
export function base58Decode(encoded: string): Uint8Array {
  if (!encoded) {
    return new Uint8Array(0);
  }
  
  // Count leading zeros
  let zeros = 0;
  for (let i = 0; i < encoded.length && encoded[i] === '1'; i++) {
    zeros++;
  }
  
  // Convert from Base58 to decimal
  let num = BigInt(0);
  for (let i = zeros; i < encoded.length; i++) {
    const charIndex = BASE58_ALPHABET.indexOf(encoded[i]);
    if (charIndex === -1) {
      throw createError(
        `Invalid Base58 character: ${encoded[i]}`,
        ErrorType.VALIDATION_ERROR
      );
    }
    num = num * BigInt(58) + BigInt(charIndex);
  }
  
  // Convert to bytes
  const bytes: number[] = [];
  while (num > BigInt(0)) {
    bytes.unshift(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }
  
  // Add leading zeros
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

// ==============================
// Key Formatting Functions
// ==============================

/**
 * Converts a private key to Wallet Import Format (WIF)
 * @param privateKey - Private key bytes
 * @param compressed - Whether to use compressed format (default: true)
 * @param testnet - Whether to use testnet version byte (default: false)
 * @returns WIF encoded private key
 */
export function privateKeyToWIF(
  privateKey: Uint8Array,
  compressed = true,
  testnet = false
): string {
  // Validate input
  if (privateKey.length !== 32) {
    throw createError(
      `Invalid private key length: ${privateKey.length} (expected 32)`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Version byte for mainnet (0x80) or testnet (0xEF)
  const versionByte = new Uint8Array([
    testnet ? BITCOIN_NETWORK.TESTNET.PRIVATE_KEY_VERSION : BITCOIN_NETWORK.MAINNET.PRIVATE_KEY_VERSION
  ]);
  
  // Compression byte (0x01) if using compressed format
  const compressionByte = compressed ? new Uint8Array([0x01]) : new Uint8Array(0);
  
  // Concatenate version byte + private key + compression byte
  const combined = new Uint8Array(
    versionByte.length + privateKey.length + compressionByte.length
  );
  combined.set(versionByte);
  combined.set(privateKey, versionByte.length);
  combined.set(compressionByte, versionByte.length + privateKey.length);
  
  // Double SHA256 for checksum
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
}

/**
 * Decodes a WIF private key to its components
 * @param wif - WIF encoded private key
 * @returns Object containing the decoded private key, compression flag, and network type
 * @throws Error if the WIF format is invalid
 */
export function wifToPrivateKey(wif: string): {
  privateKey: Uint8Array;
  compressed: boolean;
  testnet: boolean;
} {
  // Decode from base58
  const decoded = base58Decode(wif);
  
  // Check minimum length (1 byte version + 32 bytes key + 4 bytes checksum)
  if (decoded.length < 37) {
    throw createError(
      'Invalid WIF format: too short',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Check if compressed (additional compression byte before checksum)
  const compressed = decoded.length === 38;
  
  // Extract components
  const versionByte = decoded[0];
  const privateKey = decoded.slice(1, 33);
  const providedChecksum = decoded.slice(decoded.length - 4);
  
  // Verify checksum
  const dataToCheck = decoded.slice(0, decoded.length - 4);
  const calculatedChecksum = sha256(sha256(dataToCheck)).slice(0, 4);
  
  // Compare checksums
  for (let i = 0; i < 4; i++) {
    if (providedChecksum[i] !== calculatedChecksum[i]) {
      throw createError(
        'Invalid WIF format: checksum mismatch',
        ErrorType.VALIDATION_ERROR
      );
    }
  }
  
  // Determine network
  const testnet = versionByte === BITCOIN_NETWORK.TESTNET.PRIVATE_KEY_VERSION;
  
  if (versionByte !== BITCOIN_NETWORK.MAINNET.PRIVATE_KEY_VERSION && 
      versionByte !== BITCOIN_NETWORK.TESTNET.PRIVATE_KEY_VERSION) {
    throw createError(
      `Invalid WIF version byte: ${versionByte}`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  return {
    privateKey,
    compressed,
    testnet
  };
}

// ==============================
// BIP85 Child Seed Derivation
// ==============================

/**
 * Formats a BIP32 path index as a string, adding the ' symbol for hardened indices
 * @param index - BIP32 path index
 * @returns Formatted string representation
 */
export function formatHardenedPath(index: number): string {
  return index >= HARDENED_OFFSET ? `${index - HARDENED_OFFSET}'` : index.toString();
}

/**
 * Converts a normal index to a hardened index
 * @param index - Normal index
 * @returns Hardened index
 */
export function toHardened(index: number): number {
  return index + HARDENED_OFFSET;
}

/**
 * Constructs a BIP85 derivation path
 * @param index - Child index
 * @param language - BIP39 language code (default: 0 for English)
 * @param words - Number of words (12, 15, 18, 21, or 24)
 * @returns BIP85 derivation path
 */
export function constructBip85Path(
  index: number,
  language: number = 0,
  words: number = 24
): string {
  // Validate parameters using Zod schema
  const params = bip85ParamsSchema.parse({ index, language, words });
  
  // BIP-85 paths are always hardened, so we use the ' notation
  return `${BIP85.PATH_PREFIX}/${BIP85.BIP39_APP_NUMBER}'/${params.language}'/${params.words}'/${params.index}'`;
}

/**
 * Derives entropy for a BIP85 child seed
 * @param masterKey - HDKey master key
 * @param index - Child index
 * @param language - BIP39 language code (default: 0 for English)
 * @param words - Number of words (12, 15, 18, 21, or 24)
 * @returns Entropy bytes for the child seed
 */
export function deriveBip85Entropy(
  masterKey: HDKey,
  index: number,
  language: number = 0,
  words: number = 24
): Uint8Array {
  // Validate parameters using Zod schema
  const params = bip85ParamsSchema.parse({ index, language, words });
  
  // Construct the BIP85 path
  const path = constructBip85Path(params.index, params.language, params.words);
  
  // Derive the child key
  const derived = safeExec(
    () => masterKey.derive(path),
    ErrorType.DERIVATION_ERROR,
    `Failed to derive BIP85 child key for path: ${path}`
  );
  
  if (!derived.privateKey) {
    throw createError(
      'Unable to derive private key',
      ErrorType.DERIVATION_ERROR
    );
  }
  
  // As per BIP-85: HMAC-SHA512(key="bip-entropy-from-k", msg=k)
  const hmacKey = new TextEncoder().encode("bip-entropy-from-k");
  const fullEntropy = safeExec(
    () => hmac.create(sha512, hmacKey).update(derived.privateKey!).digest(),
    ErrorType.CRYPTO_ERROR,
    'Failed to generate BIP85 entropy'
  );
  
  // Return the appropriate number of bits based on word count
  const bits = BIP85_APPLICATIONS.BIP39_WORD_LENGTHS[
    `WORDS_${params.words}` as keyof typeof BIP85_APPLICATIONS.BIP39_WORD_LENGTHS
  ].bits;
  
  const result = fullEntropy.slice(0, bits / 8);
  
  // Clean up sensitive data
  clearHDKey(derived);
  
  return result;
}

/**
 * Derives a child mnemonic from a root seed phrase using BIP85
 * @param rootSeedPhrase - Root BIP39 seed phrase
 * @param path - Array of indices representing the derivation path
 * @returns Child mnemonic phrase
 */
export function deriveChildMnemonic(rootSeedPhrase: string, path: number[]): string {
  // Validate the root seed phrase
  try {
    mnemonicSchema.parse(rootSeedPhrase);
  } catch (error) {
    throw createError(
      'Invalid root seed phrase',
      ErrorType.VALIDATION_ERROR,
      error
    );
  }
  
  if (!bip39.validateMnemonic(rootSeedPhrase, wordlist)) {
    throw createError(
      'Invalid BIP39 seed phrase checksum',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Base case: if path is empty, return the root seed phrase
  if (path.length === 0) return rootSeedPhrase;
  
  // Using English 24-word mnemonics by default
  const language = BIP85_APPLICATIONS.BIP39_LANGUAGES.ENGLISH;
  const words = BIP85_APPLICATIONS.BIP39_WORD_LENGTHS.WORDS_24.words;
  
  // Recursive implementation for multi-level derivation
  let currentSeed = rootSeedPhrase;
  
  // Process each level of the path
  for (let i = 0; i < path.length; i++) {
    const seed = safeExec(
      () => bip39.mnemonicToSeedSync(currentSeed),
      ErrorType.CRYPTO_ERROR,
      'Failed to convert mnemonic to seed'
    );
    
    const masterKey = safeExec(
      () => HDKey.fromMasterSeed(seed),
      ErrorType.CRYPTO_ERROR,
      'Failed to create master key from seed'
    );
    
    const entropy = deriveBip85Entropy(masterKey, path[i], language, words);
    
    currentSeed = safeExec(
      () => bip39.entropyToMnemonic(entropy, wordlist),
      ErrorType.CRYPTO_ERROR,
      'Failed to convert entropy to mnemonic'
    );
    
    // Clean up sensitive data
    clearHDKey(masterKey);
  }
  
  return currentSeed;
}

// ==============================
// Random Generation Functions
// ==============================

/**
 * Generates cryptographically secure random bytes
 * @param length - Number of bytes to generate
 * @returns Secure random bytes
 */
export function generateRandomBytes(length: number): Uint8Array {
  if (length <= 0) {
    throw createError(
      'Length must be a positive integer',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  return safeExec(
    () => crypto.getRandomValues(new Uint8Array(length)),
    ErrorType.CRYPTO_ERROR,
    'Failed to generate random bytes'
  );
}

/**
 * Generates a random BIP39 mnemonic phrase
 * @param strength - Entropy strength in bits (128, 160, 192, 224, or 256)
 * @returns Random mnemonic phrase
 */
export function generateRandomMnemonic(strength: number = 256): string {
  // Validate strength
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw createError(
      'Invalid entropy strength. Must be 128, 160, 192, 224, or 256 bits',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Generate random entropy
  const entropy = generateRandomBytes(strength / 8);
  
  // Convert to mnemonic
  return safeExec(
    () => bip39.entropyToMnemonic(entropy, wordlist),
    ErrorType.CRYPTO_ERROR,
    'Failed to convert entropy to mnemonic'
  );
}

// ==============================
// Validation Functions
// ==============================

/**
 * Validates a BIP39 mnemonic phrase
 * @param mnemonic - Mnemonic phrase to validate
 * @returns True if valid, false otherwise
 */
export function validateMnemonic(mnemonic: string): boolean {
  try {
    // Check basic format
    mnemonicSchema.parse(mnemonic);
    
    // Check BIP39 checksum
    return bip39.validateMnemonic(mnemonic, wordlist);
  } catch (error) {
    return false;
  }
}

/**
 * Validates a BIP32 derivation path
 * @param path - Derivation path to validate
 * @returns True if valid, false otherwise
 */
export function validateDerivationPath(path: string): boolean {
  try {
    derivationPathSchema.parse(path);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Parses a BIP32 derivation path into segments
 * @param path - Derivation path string (e.g., "m/44'/0'/0'/0")
 * @returns Array of path indices with hardening applied
 * @throws Error for invalid path format
 */
export function parseDerivationPath(path: string): number[] {
  // Validate path format
  if (!validateDerivationPath(path)) {
    throw createError(
      `Invalid derivation path format: ${path}`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Remove 'm/' prefix
  const pathWithoutPrefix = path.startsWith('m/') ? path.slice(2) : path;
  
  // Handle empty path
  if (!pathWithoutPrefix) return [];
  
  // Split into segments and parse
  return pathWithoutPrefix.split('/').map(segment => {
    const hardened = segment.endsWith("'");
    const indexStr = hardened ? segment.slice(0, -1) : segment;
    const index = parseInt(indexStr, 10);
    
    if (isNaN(index) || index < 0) {
      throw createError(
        `Invalid path segment: ${segment}`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    return hardened ? index + HARDENED_OFFSET : index;
  });
}

// ==============================
// Hash Functions
// ==============================

/**
 * Computes RIPEMD160(SHA256(data))
 * @param data - Input data
 * @returns Hash160 result
 */
export function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/**
 * Computes double SHA256 hash: SHA256(SHA256(data))
 * @param data - Input data
 * @returns Double SHA256 hash
 */
export function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

// ==============================
// Test Functions
// ==============================

/**
 * Tests the BIP85 implementation against known test vectors
 * @returns True if all tests pass
 * @throws Error if any test fails
 */
export function testBip85Implementation(): boolean {
  const testMasterKey = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
  const masterKey = HDKey.fromExtendedKey(testMasterKey);
  
  // Test case 1: 12 words
  const entropy1 = deriveBip85Entropy(masterKey, 0, 0, 12);
  const expectedEntropy1 = "6250b68daf746d12a24d58b4787a714b";
  const derivedEntropy1 = bytesToHex(entropy1);
  const expectedMnemonic1 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose";
  const derivedMnemonic1 = bip39.entropyToMnemonic(entropy1, wordlist);
  
  if (derivedEntropy1 !== expectedEntropy1) {
    throw createError(
      `BIP-85 test case 1 entropy verification failed:\n      Expected: ${expectedEntropy1}\n      Got: ${derivedEntropy1}`,
      ErrorType.CRYPTO_ERROR
    );
  }
  
  if (derivedMnemonic1 !== expectedMnemonic1) {
    throw createError(
      `BIP-85 test case 1 mnemonic verification failed:\n      Expected: ${expectedMnemonic1}\n      Got: ${derivedMnemonic1}`,
      ErrorType.CRYPTO_ERROR
    );
  }
  
  // Test case 2: 24 words
  const entropy2 = deriveBip85Entropy(masterKey, 0, 0, 24);
  const expectedEntropy2 = "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f";
  const derivedEntropy2 = bytesToHex(entropy2);
  const expectedMnemonic2 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano";
  const derivedMnemonic2 = bip39.entropyToMnemonic(entropy2, wordlist);
  
  if (derivedEntropy2 !== expectedEntropy2) {
    throw createError(
      `BIP-85 test case 2 entropy verification failed:\n      Expected: ${expectedEntropy2}\n      Got: ${derivedEntropy2}`,
      ErrorType.CRYPTO_ERROR
    );
  }
  
  if (derivedMnemonic2 !== expectedMnemonic2) {
    throw createError(
      `BIP-85 test case 2 mnemonic verification failed:\n      Expected: ${expectedMnemonic2}\n      Got: ${derivedMnemonic2}`,
      ErrorType.CRYPTO_ERROR
    );
  }
  
  // Clean up sensitive data
  clearHDKey(masterKey);
  
  return true;
}
