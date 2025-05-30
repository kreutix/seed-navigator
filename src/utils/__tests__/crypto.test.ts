import { describe, it, expect, beforeEach, afterEach, vi, bench } from 'vitest';
import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import {
  base58Encode,
  base58Decode,
  privateKeyToWIF,
  wifToPrivateKey,
  formatHardenedPath,
  toHardened,
  constructBip85Path,
  deriveBip85Entropy,
  deriveChildMnemonic,
  generateRandomBytes,
  generateRandomMnemonic,
  validateMnemonic,
  validateDerivationPath,
  parseDerivationPath,
  hash160,
  sha256d,
  testBip85Implementation,
  createSecureArray,
  createSecureString,
  clearHDKey,
  createError,
  safeExec
} from '../crypto';
import { ErrorType } from '../../types';
import { HARDENED_OFFSET } from '../../constants/derivationPaths';

// Mock crypto.getRandomValues for deterministic testing
const mockGetRandomValues = vi.fn((array: Uint8Array) => {
  // Fill with predictable values based on array length
  for (let i = 0; i < array.length; i++) {
    array[i] = i % 256;
  }
  return array;
});

// Setup and teardown for crypto mocking
beforeEach(() => {
  vi.spyOn(crypto, 'getRandomValues').mockImplementation(mockGetRandomValues);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Error Handling Utilities', () => {
  it('should create typed errors', () => {
    const message = 'Test error message';
    const error = createError(message, ErrorType.VALIDATION_ERROR, { foo: 'bar' });
    
    expect(error.message).toBe(message);
    expect(error.type).toBe(ErrorType.VALIDATION_ERROR);
    expect(error.details).toEqual({ foo: 'bar' });
  });
  
  it('should safely execute functions and handle errors', () => {
    // Test successful execution
    const result = safeExec(() => 42, ErrorType.UNKNOWN_ERROR, 'Failed');
    expect(result).toBe(42);
    
    // Test error handling
    const throwingFn = () => {
      throw new Error('Original error');
    };
    
    expect(() => safeExec(throwingFn, ErrorType.CRYPTO_ERROR, 'Wrapped error'))
      .toThrow('Wrapped error');
  });
});

describe('Secure Memory Handling', () => {
  it('should create a secure array that can be cleared', () => {
    // Create from size
    const secureArray1 = createSecureArray(32);
    expect(secureArray1.data.length).toBe(32);
    
    // Fill with data
    secureArray1.data.fill(0xFF);
    expect(secureArray1.data[0]).toBe(0xFF);
    
    // Clear the data
    secureArray1.clear();
    expect(secureArray1.data[0]).toBe(0);
    
    // Create from existing array
    const initialData = new Uint8Array([1, 2, 3, 4]);
    const secureArray2 = createSecureArray(initialData);
    expect(secureArray2.data[0]).toBe(1);
    
    // Clear the data
    secureArray2.clear();
    expect(secureArray2.data[0]).toBe(0);
  });
  
  it('should create a secure string that can be cleared', () => {
    const sensitiveData = 'secret password';
    const secureString = createSecureString(sensitiveData);
    
    // Check initial value
    expect(secureString.value).toBe(sensitiveData);
    
    // Update value
    secureString.value = 'new secret';
    expect(secureString.value).toBe('new secret');
    
    // Clear the data
    secureString.clear();
    expect(secureString.value).toBe('');
  });
  
  it('should securely clear an HDKey', () => {
    // Create a test key
    const seed = bip39.mnemonicToSeedSync('test test test test test test test test test test test junk');
    const key = HDKey.fromMasterSeed(seed);
    
    // Verify key has properties
    expect(key.privateKey).toBeDefined();
    expect(key.publicKey).toBeDefined();
    
    // Clear the key
    clearHDKey(key);
    
    // Check that properties are cleared
    // Note: TypeScript will complain about accessing private properties, but we need to test this
    // @ts-ignore - Accessing private property for testing
    expect(key.privateKey).toBeUndefined();
    // @ts-ignore - Accessing private property for testing
    expect(key.publicKey).toBeUndefined();
  });
});

describe('Base58 Encoding/Decoding', () => {
  it('should encode data as Base58', () => {
    // Test vector 1: Empty array
    expect(base58Encode(new Uint8Array([]))).toBe('');
    
    // Test vector 2: Zero byte
    expect(base58Encode(new Uint8Array([0]))).toBe('1');
    
    // Test vector 3: Multiple zero bytes
    expect(base58Encode(new Uint8Array([0, 0, 0]))).toBe('111');
    
    // Test vector 4: Bitcoin address
    const addressBytes = new Uint8Array([
      0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 
      0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 
      0xEE, 0xD6, 0x19, 0x67, 0xF6
    ]);
    expect(base58Encode(addressBytes)).toBe('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM');
    
    // Test vector 5: Private key WIF
    const privateKeyBytes = new Uint8Array([
      0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x01, 0x01, 0x42, 0x3F, 0x4F, 0x18, 0x0F
    ]);
    expect(base58Encode(privateKeyBytes)).toBe('5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb');
  });
  
  it('should decode Base58 strings', () => {
    // Test vector 1: Empty string
    expect(base58Decode('')).toEqual(new Uint8Array([]));
    
    // Test vector 2: Single '1' (zero byte)
    expect(base58Decode('1')).toEqual(new Uint8Array([0]));
    
    // Test vector 3: Multiple '1's (zero bytes)
    expect(base58Decode('111')).toEqual(new Uint8Array([0, 0, 0]));
    
    // Test vector 4: Bitcoin address
    const decoded = base58Decode('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM');
    expect(bytesToHex(decoded)).toBe('00010966776006953d5567439e5e39f86a0d273beed61967f6');
    
    // Test vector 5: Decode a WIF private key
    const decodedWIF = base58Decode('5HpneLQNKrcznVCQpzodYwAmZ4AoHeyjuRf9iAHAa498rP5kuWb');
    expect(decodedWIF.length).toBe(38); // 1 version + 32 key + 1 compression + 4 checksum
    expect(decodedWIF[0]).toBe(0x80); // Mainnet private key version
  });
  
  it('should throw on invalid Base58 characters', () => {
    expect(() => base58Decode('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM0')).not.toThrow(); // Valid
    expect(() => base58Decode('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvMO')).toThrow(); // Contains 'O'
    expect(() => base58Decode('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvMI')).toThrow(); // Contains 'I'
    expect(() => base58Decode('16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvMl')).toThrow(); // Contains 'l'
  });
  
  it('should correctly round-trip Base58 encoding/decoding', () => {
    // Generate test data
    const testData = new Uint8Array(32);
    for (let i = 0; i < testData.length; i++) {
      testData[i] = i;
    }
    
    const encoded = base58Encode(testData);
    const decoded = base58Decode(encoded);
    
    expect(decoded).toEqual(testData);
  });
});

describe('WIF Key Formatting', () => {
  it('should convert private keys to WIF format', () => {
    // Test vector 1: All zeros key (mainnet, compressed)
    const privateKey1 = new Uint8Array(32).fill(0);
    const wif1 = privateKeyToWIF(privateKey1, true, false);
    expect(wif1).toBe('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn');
    
    // Test vector 2: All zeros key (mainnet, uncompressed)
    const wif2 = privateKeyToWIF(privateKey1, false, false);
    expect(wif2).toBe('5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf');
    
    // Test vector 3: All zeros key (testnet, compressed)
    const wif3 = privateKeyToWIF(privateKey1, true, true);
    expect(wif3).toBe('cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA');
    
    // Test vector 4: Key with non-zero bytes
    const privateKey2 = new Uint8Array(32);
    privateKey2[0] = 0x01;
    const wif4 = privateKeyToWIF(privateKey2, true, false);
    expect(wif4).toBe('KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74NMTptX4');
  });
  
  it('should throw on invalid private key length', () => {
    // Test with too short key
    const shortKey = new Uint8Array(31);
    expect(() => privateKeyToWIF(shortKey)).toThrow('Invalid private key length');
    
    // Test with too long key
    const longKey = new Uint8Array(33);
    expect(() => privateKeyToWIF(longKey)).toThrow('Invalid private key length');
  });
  
  it('should decode WIF private keys', () => {
    // Test vector 1: Mainnet compressed key
    const wif1 = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn';
    const { privateKey: key1, compressed: comp1, testnet: test1 } = wifToPrivateKey(wif1);
    
    expect(bytesToHex(key1)).toBe('0000000000000000000000000000000000000000000000000000000000000000');
    expect(comp1).toBe(true);
    expect(test1).toBe(false);
    
    // Test vector 2: Mainnet uncompressed key
    const wif2 = '5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf';
    const { privateKey: key2, compressed: comp2, testnet: test2 } = wifToPrivateKey(wif2);
    
    expect(bytesToHex(key2)).toBe('0000000000000000000000000000000000000000000000000000000000000000');
    expect(comp2).toBe(false);
    expect(test2).toBe(false);
    
    // Test vector 3: Testnet compressed key
    const wif3 = 'cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA';
    const { privateKey: key3, compressed: comp3, testnet: test3 } = wifToPrivateKey(wif3);
    
    expect(bytesToHex(key3)).toBe('0000000000000000000000000000000000000000000000000000000000000000');
    expect(comp3).toBe(true);
    expect(test3).toBe(true);
  });
  
  it('should throw on invalid WIF format', () => {
    // Test with invalid checksum
    const invalidChecksum = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWo'; // Changed last char
    expect(() => wifToPrivateKey(invalidChecksum)).toThrow('Invalid WIF format: checksum mismatch');
    
    // Test with invalid version byte
    const invalidVersion = 'LwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'; // Changed first char
    expect(() => wifToPrivateKey(invalidVersion)).toThrow('Invalid WIF version byte');
    
    // Test with too short WIF
    const tooShort = 'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi';
    expect(() => wifToPrivateKey(tooShort)).toThrow('Invalid WIF format: too short');
  });
  
  it('should correctly round-trip WIF encoding/decoding', () => {
    // Generate test private key
    const privateKey = new Uint8Array(32);
    for (let i = 0; i < privateKey.length; i++) {
      privateKey[i] = i;
    }
    
    // Test mainnet compressed
    const wif1 = privateKeyToWIF(privateKey, true, false);
    const decoded1 = wifToPrivateKey(wif1);
    expect(decoded1.privateKey).toEqual(privateKey);
    expect(decoded1.compressed).toBe(true);
    expect(decoded1.testnet).toBe(false);
    
    // Test testnet uncompressed
    const wif2 = privateKeyToWIF(privateKey, false, true);
    const decoded2 = wifToPrivateKey(wif2);
    expect(decoded2.privateKey).toEqual(privateKey);
    expect(decoded2.compressed).toBe(false);
    expect(decoded2.testnet).toBe(true);
  });
});

describe('BIP85 Child Seed Derivation', () => {
  it('should format hardened path indices correctly', () => {
    // Normal indices
    expect(formatHardenedPath(0)).toBe('0');
    expect(formatHardenedPath(42)).toBe('42');
    
    // Hardened indices
    expect(formatHardenedPath(HARDENED_OFFSET)).toBe('0\'');
    expect(formatHardenedPath(HARDENED_OFFSET + 42)).toBe('42\'');
  });
  
  it('should convert normal indices to hardened indices', () => {
    expect(toHardened(0)).toBe(HARDENED_OFFSET);
    expect(toHardened(42)).toBe(HARDENED_OFFSET + 42);
  });
  
  it('should construct valid BIP85 paths', () => {
    // Default parameters (English, 24 words)
    expect(constructBip85Path(0)).toBe('m/83696968\'/39\'/0\'/24\'/0\'');
    
    // Custom language and word count
    expect(constructBip85Path(42, 1, 12)).toBe('m/83696968\'/39\'/1\'/12\'/42\'');
  });
  
  it('should throw on invalid BIP85 parameters', () => {
    // Invalid index (too large)
    expect(() => constructBip85Path(0x80000000)).toThrow();
    
    // Invalid language
    expect(() => constructBip85Path(0, 10)).toThrow();
    
    // Invalid word count
    expect(() => constructBip85Path(0, 0, 13)).toThrow();
  });
  
  it('should derive BIP85 entropy correctly using test vectors', () => {
    // BIP85 test vector from the specification
    const testMasterKey = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb";
    const masterKey = HDKey.fromExtendedKey(testMasterKey);
    
    // Test vector 1: 12 words
    const entropy1 = deriveBip85Entropy(masterKey, 0, 0, 12);
    const expectedEntropy1 = "6250b68daf746d12a24d58b4787a714b";
    const derivedEntropy1 = bytesToHex(entropy1);
    const expectedMnemonic1 = "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose";
    const derivedMnemonic1 = bip39.entropyToMnemonic(entropy1, wordlist);
    
    expect(derivedEntropy1).toBe(expectedEntropy1);
    expect(derivedMnemonic1).toBe(expectedMnemonic1);
    
    // Test vector 2: 24 words
    const entropy2 = deriveBip85Entropy(masterKey, 0, 0, 24);
    const expectedEntropy2 = "ae131e2312cdc61331542efe0d1077bac5ea803adf24b313a4f0e48e9c51f37f";
    const derivedEntropy2 = bytesToHex(entropy2);
    const expectedMnemonic2 = "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano";
    const derivedMnemonic2 = bip39.entropyToMnemonic(entropy2, wordlist);
    
    expect(derivedEntropy2).toBe(expectedEntropy2);
    expect(derivedMnemonic2).toBe(expectedMnemonic2);
  });
  
  it('should throw when deriving with invalid master key', () => {
    // Create a master key without a private key
    const publicOnlyKey = new HDKey();
    publicOnlyKey.publicKey = new Uint8Array(33).fill(1);
    
    expect(() => deriveBip85Entropy(publicOnlyKey, 0)).toThrow('Unable to derive private key');
  });
  
  it('should derive child mnemonics correctly', () => {
    // Create a known root seed
    const rootSeed = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    
    // Test base case: empty path returns the root seed
    expect(deriveChildMnemonic(rootSeed, [])).toBe(rootSeed);
    
    // Test single-level derivation
    const child0 = deriveChildMnemonic(rootSeed, [0]);
    expect(validateMnemonic(child0)).toBe(true);
    expect(child0.split(' ').length).toBe(24); // Should be 24 words
    
    // Test multi-level derivation
    const child01 = deriveChildMnemonic(rootSeed, [0, 1]);
    expect(validateMnemonic(child01)).toBe(true);
    expect(child01.split(' ').length).toBe(24);
    
    // Verify deterministic derivation (same path always gives same result)
    expect(deriveChildMnemonic(rootSeed, [0, 1])).toBe(child01);
  });
  
  it('should throw on invalid root seed phrase', () => {
    // Invalid word count
    const invalidWordCount = 'abandon abandon abandon';
    expect(() => deriveChildMnemonic(invalidWordCount, [0])).toThrow();
    
    // Invalid checksum
    const invalidChecksum = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
    expect(() => deriveChildMnemonic(invalidChecksum, [0])).toThrow();
  });
  
  it('should run the BIP85 implementation test successfully', () => {
    expect(testBip85Implementation()).toBe(true);
  });
});

describe('Random Generation Functions', () => {
  it('should generate random bytes of the requested length', () => {
    const bytes = generateRandomBytes(32);
    expect(bytes.length).toBe(32);
    
    // With our mock, the bytes should be 0, 1, 2, ..., 31
    for (let i = 0; i < 32; i++) {
      expect(bytes[i]).toBe(i);
    }
    
    // Verify crypto.getRandomValues was called correctly
    expect(mockGetRandomValues).toHaveBeenCalledWith(expect.any(Uint8Array));
    expect(mockGetRandomValues.mock.calls[0][0].length).toBe(32);
  });
  
  it('should throw on invalid length', () => {
    expect(() => generateRandomBytes(0)).toThrow();
    expect(() => generateRandomBytes(-1)).toThrow();
  });
  
  it('should generate random mnemonics with the requested strength', () => {
    // Test 128-bit entropy (12 words)
    const mnemonic12 = generateRandomMnemonic(128);
    expect(mnemonic12.split(' ').length).toBe(12);
    expect(validateMnemonic(mnemonic12)).toBe(true);
    
    // Test 256-bit entropy (24 words)
    const mnemonic24 = generateRandomMnemonic(256);
    expect(mnemonic24.split(' ').length).toBe(24);
    expect(validateMnemonic(mnemonic24)).toBe(true);
    
    // Test default (256-bit)
    const mnemonicDefault = generateRandomMnemonic();
    expect(mnemonicDefault.split(' ').length).toBe(24);
    expect(validateMnemonic(mnemonicDefault)).toBe(true);
  });
  
  it('should throw on invalid entropy strength', () => {
    expect(() => generateRandomMnemonic(129)).toThrow();
    expect(() => generateRandomMnemonic(0)).toThrow();
  });
});

describe('Validation Functions', () => {
  it('should validate BIP39 mnemonics', () => {
    // Valid mnemonics
    expect(validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')).toBe(true);
    expect(validateMnemonic('legal winner thank year wave sausage worth useful legal winner thank yellow')).toBe(true);
    
    // Invalid word count
    expect(validateMnemonic('abandon')).toBe(false);
    expect(validateMnemonic('abandon abandon abandon')).toBe(false);
    
    // Invalid checksum
    expect(validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon')).toBe(false);
    
    // Invalid words
    expect(validateMnemonic('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bitcoin')).toBe(false);
  });
  
  it('should validate BIP32 derivation paths', () => {
    // Valid paths
    expect(validateDerivationPath('m/0')).toBe(true);
    expect(validateDerivationPath('m/0/1')).toBe(true);
    expect(validateDerivationPath('m/0\'/1\'')).toBe(true);
    expect(validateDerivationPath('m/44\'/0\'/0\'/0/0')).toBe(true);
    
    // Invalid paths
    expect(validateDerivationPath('')).toBe(false);
    expect(validateDerivationPath('0/1')).toBe(false); // Missing 'm/'
    expect(validateDerivationPath('m/0/"')).toBe(false); // Invalid hardened notation
    expect(validateDerivationPath('m/-1')).toBe(false); // Negative index
    expect(validateDerivationPath('m/abc')).toBe(false); // Non-numeric
  });
  
  it('should parse derivation paths correctly', () => {
    // Simple path
    expect(parseDerivationPath('m/0')).toEqual([0]);
    
    // Multiple indices
    expect(parseDerivationPath('m/0/1')).toEqual([0, 1]);
    
    // Hardened indices
    expect(parseDerivationPath('m/0\'')).toEqual([HARDENED_OFFSET]);
    expect(parseDerivationPath('m/0\'/1\'')).toEqual([HARDENED_OFFSET, HARDENED_OFFSET + 1]);
    
    // Mixed normal and hardened
    expect(parseDerivationPath('m/44\'/0\'/0\'/0/1')).toEqual([
      HARDENED_OFFSET + 44,
      HARDENED_OFFSET,
      HARDENED_OFFSET,
      0,
      1
    ]);
    
    // Empty path
    expect(parseDerivationPath('m/')).toEqual([]);
    expect(parseDerivationPath('m')).toEqual([]);
  });
  
  it('should throw on invalid derivation path format', () => {
    expect(() => parseDerivationPath('0/1')).toThrow(); // Missing 'm/'
    expect(() => parseDerivationPath('m/abc')).toThrow(); // Non-numeric
    expect(() => parseDerivationPath('m/-1')).toThrow(); // Negative index
  });
});

describe('Hash Functions', () => {
  it('should compute hash160 correctly', () => {
    // Test vector: hash160 of "hello world"
    const data = new TextEncoder().encode('hello world');
    const hash = hash160(data);
    expect(bytesToHex(hash)).toBe('d7d5ee7824ff93f94c3055af9382c86c68b5ca92');
  });
  
  it('should compute double SHA256 correctly', () => {
    // Test vector: double SHA256 of "hello world"
    const data = new TextEncoder().encode('hello world');
    const hash = sha256d(data);
    expect(bytesToHex(hash)).toBe('bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423');
  });
});

describe('Performance Tests', () => {
  bench('BIP85 derivation (12 words)', () => {
    const seed = bip39.mnemonicToSeedSync('test test test test test test test test test test test junk');
    const masterKey = HDKey.fromMasterSeed(seed);
    deriveBip85Entropy(masterKey, 0, 0, 12);
    clearHDKey(masterKey);
  });
  
  bench('BIP85 derivation (24 words)', () => {
    const seed = bip39.mnemonicToSeedSync('test test test test test test test test test test test junk');
    const masterKey = HDKey.fromMasterSeed(seed);
    deriveBip85Entropy(masterKey, 0, 0, 24);
    clearHDKey(masterKey);
  });
  
  bench('Base58 encoding (32 bytes)', () => {
    const data = new Uint8Array(32).fill(1);
    base58Encode(data);
  });
  
  bench('Base58 decoding (32 bytes equivalent)', () => {
    const encoded = base58Encode(new Uint8Array(32).fill(1));
    base58Decode(encoded);
  });
  
  bench('WIF encoding', () => {
    const privateKey = new Uint8Array(32).fill(1);
    privateKeyToWIF(privateKey);
  });
  
  bench('WIF decoding', () => {
    const wif = privateKeyToWIF(new Uint8Array(32).fill(1));
    wifToPrivateKey(wif);
  });
  
  bench('Child mnemonic derivation (single level)', () => {
    const rootSeed = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    deriveChildMnemonic(rootSeed, [0]);
  });
  
  bench('Child mnemonic derivation (multi level)', () => {
    const rootSeed = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    deriveChildMnemonic(rootSeed, [0, 1, 2]);
  });
});
