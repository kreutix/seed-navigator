import { describe, it, expect, beforeEach, afterEach, vi, bench } from 'vitest';
import { HDKey } from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

import {
  isBitcoinPath,
  getBitcoinAddressType,
  getPathType,
  createP2PKHAddress,
  createP2SHAddress,
  createP2WPKHAddress,
  createP2TRAddress,
  deriveBitcoinKeys,
  createBitcoinPath,
  testBitcoinImplementation
} from '../bitcoin';
import { clearHDKey } from '../crypto';
import { BitcoinAddressType } from '../../types';
import {
  BITCOIN_PURPOSE,
  COIN_TYPE,
  PATH_PATTERNS
} from '../../constants/derivationPaths';

// Test vectors from Bitcoin documentation and real-world examples
const TEST_VECTORS = {
  // BIP32 test vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
  BIP32_VECTOR_1: {
    seed: '000102030405060708090a0b0c0d0e0f',
    masterKey: 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    derivedKeys: {
      'm/0\'': 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
      'm/0\'/1': 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
      'm/0\'/1/2\'': 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
      'm/0\'/1/2\'/2': 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
      'm/0\'/1/2\'/2/1000000000': 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'
    }
  },
  
  // Bitcoin address test vectors
  P2PKH: {
    pubKeyHash: '751e76e8199196d454941c45d1b3a323f1433bd6', // RIPEMD160(SHA256(pubKey))
    address: '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
  },
  P2SH: {
    scriptHash: 'cd639a8d3d2322b68ee489465dd3060d1a8b0c37', // RIPEMD160(SHA256(redeemScript))
    address: '3LDjPfKXJVkAZMVBK5ZUFqcBGJeZqXpXTL'
  },
  P2WPKH: {
    pubKeyHash: '751e76e8199196d454941c45d1b3a323f1433bd6',
    address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'
  },
  P2TR: {
    xOnlyPubKey: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', // x-coordinate of secp256k1 generator point
    address: 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'
  }
};

// Helper function to create a test HDKey
function createTestHDKey(mnemonic = 'test test test test test test test test test test test junk') {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  return HDKey.fromMasterSeed(seed);
}

describe('Path Detection and Validation', () => {
  it('should correctly identify Bitcoin paths', () => {
    // Bitcoin paths
    expect(isBitcoinPath(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe(true);
    expect(isBitcoinPath(`m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe(true);
    expect(isBitcoinPath(`m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe(true);
    expect(isBitcoinPath(`m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe(true);
    
    // Non-Bitcoin paths
    expect(isBitcoinPath(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0`)).toBe(false);
    expect(isBitcoinPath(`m/0/0`)).toBe(false);
    expect(isBitcoinPath(`m/1'/2'/3'`)).toBe(false);
  });
  
  it('should correctly determine Bitcoin address type from path', () => {
    // Legacy (P2PKH)
    expect(getBitcoinAddressType(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0`))
      .toBe(BitcoinAddressType.P2PKH);
    
    // Nested SegWit (P2SH-P2WPKH)
    expect(getBitcoinAddressType(`m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`))
      .toBe(BitcoinAddressType.P2SH_P2WPKH);
    
    // Native SegWit (P2WPKH)
    expect(getBitcoinAddressType(`m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`))
      .toBe(BitcoinAddressType.P2WPKH);
    
    // Taproot (P2TR)
    expect(getBitcoinAddressType(`m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0`))
      .toBe(BitcoinAddressType.P2TR);
    
    // Non-Bitcoin path
    expect(getBitcoinAddressType(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0`))
      .toBeUndefined();
  });
  
  it('should correctly determine path type', () => {
    // Bitcoin paths
    expect(getPathType(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe('bitcoin');
    expect(getPathType(`m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe('bitcoin');
    expect(getPathType(`m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe('bitcoin');
    expect(getPathType(`m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0`)).toBe('bitcoin');
    
    // Nostr path
    expect(getPathType(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0`)).toBe('nostr');
    
    // Unknown path
    expect(getPathType(`m/0/0`)).toBe('unknown');
    expect(getPathType(`m/1'/2'/3'`)).toBe('unknown');
  });
  
  it('should create valid Bitcoin paths', () => {
    // Legacy (P2PKH)
    expect(createBitcoinPath(BITCOIN_PURPOSE.LEGACY))
      .toBe(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    
    // Nested SegWit (P2SH-P2WPKH)
    expect(createBitcoinPath(BITCOIN_PURPOSE.NESTED_SEGWIT, 1, 1, 5))
      .toBe(`m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/1'/1/5`);
    
    // Native SegWit (P2WPKH)
    expect(createBitcoinPath(BITCOIN_PURPOSE.NATIVE_SEGWIT, 2, 0, 10))
      .toBe(`m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/2'/0/10`);
    
    // Taproot (P2TR)
    expect(createBitcoinPath(BITCOIN_PURPOSE.TAPROOT, 0, 1, 0))
      .toBe(`m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/1/0`);
    
    // Testnet
    expect(createBitcoinPath(BITCOIN_PURPOSE.LEGACY, 0, 0, 0, true))
      .toBe(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN_TESTNET}'/0'/0/0`);
  });
  
  it('should throw on invalid Bitcoin path parameters', () => {
    // Invalid purpose
    expect(() => createBitcoinPath(45)).toThrow('Invalid purpose value');
    
    // Negative indices
    expect(() => createBitcoinPath(BITCOIN_PURPOSE.LEGACY, -1)).toThrow('Indices must be non-negative');
    expect(() => createBitcoinPath(BITCOIN_PURPOSE.LEGACY, 0, -1)).toThrow('Indices must be non-negative');
    expect(() => createBitcoinPath(BITCOIN_PURPOSE.LEGACY, 0, 0, -1)).toThrow('Indices must be non-negative');
    
    // Invalid change value
    expect(() => createBitcoinPath(BITCOIN_PURPOSE.LEGACY, 0, 2)).toThrow('Change value must be 0 (external) or 1 (internal/change)');
  });
});

describe('Bitcoin Address Generation', () => {
  it('should generate P2PKH addresses correctly', () => {
    // Test with known test vector
    const pubkeyHash = hexToBytes(TEST_VECTORS.P2PKH.pubKeyHash);
    const address = createP2PKHAddress(pubkeyHash);
    expect(address).toBe(TEST_VECTORS.P2PKH.address);
    
    // Test testnet address
    const testnetAddress = createP2PKHAddress(pubkeyHash, true);
    expect(testnetAddress).not.toBe(address); // Should be different
    expect(testnetAddress.startsWith('m') || testnetAddress.startsWith('n')).toBe(true);
  });
  
  it('should generate P2SH-P2WPKH addresses correctly', () => {
    // Create a pubkey hash
    const pubkeyHash = hexToBytes(TEST_VECTORS.P2PKH.pubKeyHash);
    
    // Generate P2SH-P2WPKH address
    const { address, witnessProgram, checksum } = createP2SHAddress(pubkeyHash);
    
    // Verify address format
    expect(address.startsWith('3')).toBe(true);
    
    // Verify witness program format (0014 + pubKeyHash)
    expect(witnessProgram.startsWith('0014')).toBe(true);
    expect(witnessProgram.length).toBe(44); // 4 chars for prefix + 40 chars for 20-byte pubkeyHash
    
    // Verify checksum is present
    expect(checksum.length).toBe(8); // 4 bytes = 8 hex chars
    
    // Test testnet address
    const testnetResult = createP2SHAddress(pubkeyHash, true);
    expect(testnetResult.address.startsWith('2')).toBe(true);
  });
  
  it('should generate P2WPKH addresses correctly', () => {
    // Test with known test vector
    const pubkeyHash = hexToBytes(TEST_VECTORS.P2WPKH.pubKeyHash);
    const { address, witnessProgram } = createP2WPKHAddress(pubkeyHash);
    
    // Verify address format
    expect(address.startsWith('bc1q')).toBe(true);
    
    // Verify witness program format (0014 + pubKeyHash)
    expect(witnessProgram.startsWith('0014')).toBe(true);
    expect(witnessProgram.length).toBe(44); // 4 chars for prefix + 40 chars for 20-byte pubkeyHash
    
    // Test testnet address
    const testnetResult = createP2WPKHAddress(pubkeyHash, true);
    expect(testnetResult.address.startsWith('tb1q')).toBe(true);
  });
  
  it('should generate P2TR addresses correctly', () => {
    // Create a compressed public key (33 bytes)
    const compressedPubKey = new Uint8Array(33);
    compressedPubKey[0] = 0x02; // Even y-coordinate
    compressedPubKey.set(hexToBytes(TEST_VECTORS.P2TR.xOnlyPubKey), 1);
    
    // Generate P2TR address
    const { address, witnessProgram } = createP2TRAddress(compressedPubKey);
    
    // Verify address format
    expect(address.startsWith('bc1p')).toBe(true);
    
    // Verify witness program format (5120 + xOnlyPubKey)
    expect(witnessProgram.startsWith('5120')).toBe(true);
    expect(witnessProgram.length).toBe(68); // 4 chars for prefix + 64 chars for 32-byte x-only pubkey
    
    // Test testnet address
    const testnetResult = createP2TRAddress(compressedPubKey, true);
    expect(testnetResult.address.startsWith('tb1p')).toBe(true);
  });
  
  it('should throw on invalid P2TR public key length', () => {
    // Test with invalid public key length
    const invalidPubKey = new Uint8Array(32); // Should be 33 bytes
    expect(() => createP2TRAddress(invalidPubKey)).toThrow('Taproot requires a 33-byte compressed public key');
  });
});

describe('Bitcoin Key Derivation', () => {
  it('should derive Bitcoin keys from HDKey and path', () => {
    const masterKey = createTestHDKey();
    
    // Test P2PKH derivation
    const p2pkhKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    expect(p2pkhKeys.address.startsWith('1')).toBe(true);
    expect(p2pkhKeys.privateKeyWIF.startsWith('K') || p2pkhKeys.privateKeyWIF.startsWith('L')).toBe(true);
    expect(p2pkhKeys.publicKey.length).toBe(66); // 33 bytes = 66 hex chars
    
    // Test P2SH-P2WPKH derivation
    const p2shKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    expect(p2shKeys.address.startsWith('3')).toBe(true);
    expect(p2shKeys.witnessProgram.startsWith('0014')).toBe(true);
    
    // Test P2WPKH derivation
    const p2wpkhKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    expect(p2wpkhKeys.address.startsWith('bc1q')).toBe(true);
    expect(p2wpkhKeys.witnessProgram.startsWith('0014')).toBe(true);
    
    // Test P2TR derivation
    const p2trKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    expect(p2trKeys.address.startsWith('bc1p')).toBe(true);
    expect(p2trKeys.witnessProgram.startsWith('5120')).toBe(true);
    
    // Clean up
    clearHDKey(masterKey);
  });
  
  it('should derive testnet Bitcoin keys', () => {
    const masterKey = createTestHDKey();
    
    // Test P2PKH testnet derivation
    const p2pkhKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN_TESTNET}'/0'/0/0`, true);
    expect(p2pkhKeys.address.startsWith('m') || p2pkhKeys.address.startsWith('n')).toBe(true);
    
    // Test P2WPKH testnet derivation
    const p2wpkhKeys = deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN_TESTNET}'/0'/0/0`, true);
    expect(p2wpkhKeys.address.startsWith('tb1q')).toBe(true);
    
    // Clean up
    clearHDKey(masterKey);
  });
  
  it('should throw on unsupported derivation path', () => {
    const masterKey = createTestHDKey();
    
    // Test with unsupported path
    expect(() => deriveBitcoinKeys(masterKey, 'm/0/0')).toThrow('Unsupported derivation path for Bitcoin');
    
    // Clean up
    clearHDKey(masterKey);
  });
  
  it('should throw when derived key is missing private or public key', () => {
    // Create a public-only HDKey
    const publicOnlyKey = new HDKey();
    publicOnlyKey.publicKey = new Uint8Array(33).fill(1);
    
    // Should throw when deriving
    expect(() => deriveBitcoinKeys(publicOnlyKey, `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0/0`))
      .toThrow('Failed to derive key');
  });
  
  it('should run the Bitcoin implementation test successfully', () => {
    expect(testBitcoinImplementation()).toBe(true);
  });
});

describe('Derivation with BIP32 Test Vectors', () => {
  let masterKey: HDKey;
  
  beforeEach(() => {
    // Create master key from BIP32 test vector 1
    const seed = hexToBytes(TEST_VECTORS.BIP32_VECTOR_1.seed);
    masterKey = HDKey.fromMasterSeed(seed);
    expect(masterKey.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.masterKey);
  });
  
  afterEach(() => {
    clearHDKey(masterKey);
  });
  
  it('should derive keys matching BIP32 test vectors', () => {
    // Derive m/0'
    const child1 = masterKey.derive("m/0'");
    expect(child1.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.derivedKeys["m/0'"]);
    
    // Derive m/0'/1
    const child2 = masterKey.derive("m/0'/1");
    expect(child2.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.derivedKeys["m/0'/1"]);
    
    // Derive m/0'/1/2'
    const child3 = masterKey.derive("m/0'/1/2'");
    expect(child3.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.derivedKeys["m/0'/1/2'"]);
    
    // Derive m/0'/1/2'/2
    const child4 = masterKey.derive("m/0'/1/2'/2");
    expect(child4.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.derivedKeys["m/0'/1/2'/2"]);
    
    // Derive m/0'/1/2'/2/1000000000
    const child5 = masterKey.derive("m/0'/1/2'/2/1000000000");
    expect(child5.privateExtendedKey).toBe(TEST_VECTORS.BIP32_VECTOR_1.derivedKeys["m/0'/1/2'/2/1000000000"]);
  });
  
  it('should derive Bitcoin addresses from BIP32 test vectors', () => {
    // Derive a key from the test vector
    const child = masterKey.derive("m/0'/1/2'/2");
    
    // Derive Bitcoin keys for different address types
    const p2pkhKeys = deriveBitcoinKeys(child, `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    const p2shKeys = deriveBitcoinKeys(child, `m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    const p2wpkhKeys = deriveBitcoinKeys(child, `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    const p2trKeys = deriveBitcoinKeys(child, `m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
    
    // Verify address formats
    expect(p2pkhKeys.address.startsWith('1')).toBe(true);
    expect(p2shKeys.address.startsWith('3')).toBe(true);
    expect(p2wpkhKeys.address.startsWith('bc1q')).toBe(true);
    expect(p2trKeys.address.startsWith('bc1p')).toBe(true);
    
    // Verify private keys are derived
    expect(p2pkhKeys.privateKeyWIF).toBeTruthy();
    expect(p2shKeys.privateKeyWIF).toBeTruthy();
    expect(p2wpkhKeys.privateKeyWIF).toBeTruthy();
    expect(p2trKeys.privateKeyWIF).toBeTruthy();
    
    // Clean up
    clearHDKey(child);
  });
});

describe('Performance Tests', () => {
  let masterKey: HDKey;
  
  beforeEach(() => {
    masterKey = createTestHDKey();
  });
  
  afterEach(() => {
    clearHDKey(masterKey);
  });
  
  bench('P2PKH address generation', () => {
    deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
  });
  
  bench('P2SH-P2WPKH address generation', () => {
    deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
  });
  
  bench('P2WPKH address generation', () => {
    deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
  });
  
  bench('P2TR address generation', () => {
    deriveBitcoinKeys(masterKey, `m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0/0`);
  });
  
  bench('Path type detection', () => {
    for (let i = 0; i < 100; i++) {
      getPathType(`m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0/${i}`);
    }
  });
  
  bench('Bitcoin path creation', () => {
    for (let i = 0; i < 100; i++) {
      createBitcoinPath(BITCOIN_PURPOSE.NATIVE_SEGWIT, 0, 0, i);
    }
  });
});
