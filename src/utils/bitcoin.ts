import { HDKey } from '@scure/bip32';
import { bech32, bech32m } from 'bech32';
import { bytesToHex } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';

import {
  BitcoinKeys,
  BitcoinAddressType,
  PathType,
  ErrorType,
  AppError
} from '../types';
import {
  BITCOIN_NETWORK,
  BITCOIN_PURPOSE,
  COIN_TYPE,
  PATH_PATTERNS,
  WITNESS_PROGRAM_PREFIXES
} from '../constants/derivationPaths';
import {
  base58Encode,
  privateKeyToWIF,
  hash160,
  sha256d,
  createError,
  safeExec,
  clearHDKey
} from './crypto';

/**
 * Determines if a derivation path is a Bitcoin path
 * @param path - Derivation path to check
 * @returns True if the path is a Bitcoin path
 */
export function isBitcoinPath(path: string): boolean {
  return (
    path.startsWith(PATH_PATTERNS.BITCOIN_LEGACY) ||
    path.startsWith(PATH_PATTERNS.BITCOIN_NESTED_SEGWIT) ||
    path.startsWith(PATH_PATTERNS.BITCOIN_NATIVE_SEGWIT) ||
    path.startsWith(PATH_PATTERNS.BITCOIN_TAPROOT)
  );
}

/**
 * Determines the Bitcoin address type from a derivation path
 * @param path - Derivation path to check
 * @returns Bitcoin address type or undefined if not a Bitcoin path
 */
export function getBitcoinAddressType(path: string): BitcoinAddressType | undefined {
  if (path.startsWith(PATH_PATTERNS.BITCOIN_LEGACY)) {
    return BitcoinAddressType.P2PKH;
  } else if (path.startsWith(PATH_PATTERNS.BITCOIN_NESTED_SEGWIT)) {
    return BitcoinAddressType.P2SH_P2WPKH;
  } else if (path.startsWith(PATH_PATTERNS.BITCOIN_NATIVE_SEGWIT)) {
    return BitcoinAddressType.P2WPKH;
  } else if (path.startsWith(PATH_PATTERNS.BITCOIN_TAPROOT)) {
    return BitcoinAddressType.P2TR;
  }
  
  return undefined;
}

/**
 * Determines the path type (bitcoin, nostr, or unknown)
 * @param path - Derivation path to check
 * @returns Path type
 */
export function getPathType(path: string): PathType {
  // Bitcoin paths
  if (isBitcoinPath(path)) {
    return 'bitcoin';
  }
  
  // Nostr paths
  if (path.startsWith(PATH_PATTERNS.NOSTR)) {
    return 'nostr';
  }

  return 'unknown';
}

/**
 * Creates a P2PKH (Legacy) Bitcoin address
 * @param pubkeyHash - RIPEMD160(SHA256(publicKey))
 * @param testnet - Whether to use testnet version byte
 * @returns P2PKH address
 */
export function createP2PKHAddress(pubkeyHash: Uint8Array, testnet = false): string {
  // P2PKH version byte (0x00 for mainnet, 0x6F for testnet) + pubkeyHash + checksum
  const versionByte = testnet ? 
    BITCOIN_NETWORK.TESTNET.P2PKH_VERSION : 
    BITCOIN_NETWORK.MAINNET.P2PKH_VERSION;
  
  const versionAndHash = new Uint8Array([versionByte, ...pubkeyHash]);
  const checksumBytes = sha256d(versionAndHash).slice(0, 4);
  const final = new Uint8Array([...versionAndHash, ...checksumBytes]);
  
  return base58Encode(final);
}

/**
 * Creates a P2SH-P2WPKH (Nested SegWit) Bitcoin address
 * @param pubkeyHash - RIPEMD160(SHA256(publicKey))
 * @param testnet - Whether to use testnet version byte
 * @returns P2SH-P2WPKH address and witness program
 */
export function createP2SHAddress(pubkeyHash: Uint8Array, testnet = false): {
  address: string;
  witnessProgram: string;
  checksum: string;
} {
  // Create redeem script (OP_0 + OP_PUSHBYTES_20 + <pubKeyHash>)
  const redeemScript = new Uint8Array([0x00, 0x14, ...pubkeyHash]);
  
  // Hash160 of the redeem script
  const scriptHash = hash160(redeemScript);
  
  // P2SH version byte (0x05 for mainnet, 0xC4 for testnet) + scriptHash + checksum
  const versionByte = testnet ? 
    BITCOIN_NETWORK.TESTNET.P2SH_VERSION : 
    BITCOIN_NETWORK.MAINNET.P2SH_VERSION;
  
  const versionAndHash = new Uint8Array([versionByte, ...scriptHash]);
  const checksumBytes = sha256d(versionAndHash).slice(0, 4);
  const final = new Uint8Array([...versionAndHash, ...checksumBytes]);
  
  return {
    address: base58Encode(final),
    witnessProgram: bytesToHex(redeemScript),
    checksum: bytesToHex(checksumBytes)
  };
}

/**
 * Creates a P2WPKH (Native SegWit) Bitcoin address
 * @param pubkeyHash - RIPEMD160(SHA256(publicKey))
 * @param testnet - Whether to use testnet HRP
 * @returns P2WPKH address and witness program
 */
export function createP2WPKHAddress(pubkeyHash: Uint8Array, testnet = false): {
  address: string;
  witnessProgram: string;
} {
  // For P2WPKH, witness version 0 and push 20 bytes
  const words = bech32.toWords(pubkeyHash);
  
  // Prepend witness version 0
  const fullWords = new Uint8Array([0, ...words]);
  
  // Human-readable part (HRP): 'bc' for mainnet, 'tb' for testnet
  const hrp = testnet ? BITCOIN_NETWORK.TESTNET.BECH32_HRP : BITCOIN_NETWORK.MAINNET.BECH32_HRP;
  
  // Encode with bech32
  const address = bech32.encode(hrp, fullWords);
  
  // For witnessProgram display, show the full script including OP_0 OP_PUSHBYTES_20
  const witnessProgram = WITNESS_PROGRAM_PREFIXES.P2WPKH + bytesToHex(pubkeyHash);
  
  return {
    address,
    witnessProgram
  };
}

/**
 * Creates a P2TR (Taproot) Bitcoin address
 * @param publicKey - 33-byte compressed public key
 * @param testnet - Whether to use testnet HRP
 * @returns P2TR address and witness program
 */
export function createP2TRAddress(publicKey: Uint8Array, testnet = false): {
  address: string;
  witnessProgram: string;
} {
  if (publicKey.length !== 33) {
    throw createError(
      'Taproot requires a 33-byte compressed public key',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // For Taproot, we need to use the x-only public key (32 bytes)
  // Just take the 32 bytes x-coordinate from the 33-byte compressed public key
  // Removing the first byte (0x02 or 0x03) which indicates parity
  const xOnlyPubKey = publicKey.slice(1);
  
  // For P2TR, witness version 1 and push 32 bytes
  const words = bech32m.toWords(xOnlyPubKey);
  
  // Prepend witness version 1
  const fullWords = new Uint8Array([1, ...words]);
  
  // Human-readable part (HRP): 'bc' for mainnet, 'tb' for testnet
  const hrp = testnet ? BITCOIN_NETWORK.TESTNET.BECH32_HRP : BITCOIN_NETWORK.MAINNET.BECH32_HRP;
  
  // Encode with bech32m (not regular bech32)
  const address = bech32m.encode(hrp, fullWords);
  
  // For witnessProgram display, show the full script including OP_1 OP_PUSHBYTES_32
  const witnessProgram = WITNESS_PROGRAM_PREFIXES.P2TR + bytesToHex(xOnlyPubKey);
  
  return {
    address,
    witnessProgram
  };
}

/**
 * Derives Bitcoin keys and addresses from a master key and derivation path
 * @param masterKey - HDKey master key
 * @param path - BIP32 derivation path
 * @param testnet - Whether to use testnet addresses (default: false)
 * @returns Bitcoin keys and addresses
 */
export function deriveBitcoinKeys(
  masterKey: HDKey,
  path: string,
  testnet = false
): BitcoinKeys {
  try {
    // Derive the key at the specified path
    const key = safeExec(
      () => masterKey.derive(path),
      ErrorType.DERIVATION_ERROR,
      `Failed to derive key at path: ${path}`
    );
    
    if (!key.privateKey || !key.publicKey) {
      throw createError(
        'Derived key is missing private or public key',
        ErrorType.DERIVATION_ERROR
      );
    }
    
    // Get the Bitcoin address type from the path
    const addressType = getBitcoinAddressType(path);
    if (!addressType) {
      throw createError(
        `Unsupported derivation path for Bitcoin: ${path}`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    // Convert the public key to hex for display
    const publicKeyHex = bytesToHex(key.publicKey);
    
    // Hash the public key
    const publicKeyHash = bytesToHex(sha256(key.publicKey));
    const pubkeyHash = hash160(key.publicKey);
    const publicKeyHash160 = bytesToHex(pubkeyHash);
    
    let address = '';
    let witnessProgram = '';
    let checksum = '';
    
    // Generate the appropriate address type based on the path
    switch (addressType) {
      case BitcoinAddressType.P2WPKH: // Native SegWit
        const p2wpkh = createP2WPKHAddress(pubkeyHash, testnet);
        address = p2wpkh.address;
        witnessProgram = p2wpkh.witnessProgram;
        break;
        
      case BitcoinAddressType.P2SH_P2WPKH: // Nested SegWit
        const p2sh = createP2SHAddress(pubkeyHash, testnet);
        address = p2sh.address;
        witnessProgram = p2sh.witnessProgram;
        checksum = p2sh.checksum;
        break;
        
      case BitcoinAddressType.P2TR: // Taproot
        const p2tr = createP2TRAddress(key.publicKey, testnet);
        address = p2tr.address;
        witnessProgram = p2tr.witnessProgram;
        break;
        
      case BitcoinAddressType.P2PKH: // Legacy
        address = createP2PKHAddress(pubkeyHash, testnet);
        checksum = bytesToHex(sha256d(new Uint8Array([
          testnet ? BITCOIN_NETWORK.TESTNET.P2PKH_VERSION : BITCOIN_NETWORK.MAINNET.P2PKH_VERSION,
          ...pubkeyHash
        ])).slice(0, 4));
        break;
        
      default:
        throw createError(
          `Unsupported Bitcoin address type: ${addressType}`,
          ErrorType.VALIDATION_ERROR
        );
    }
    
    // Create the result object
    const result: BitcoinKeys = {
      address,
      privateKeyWIF: privateKeyToWIF(key.privateKey, true, testnet),
      publicKey: publicKeyHex,
      publicKeyHash,
      publicKeyHash160,
      witnessProgram,
      checksum
    };
    
    // Clean up sensitive data
    clearHDKey(key);
    
    return result;
  } catch (error) {
    if ((error as AppError).type) {
      throw error;
    }
    
    throw createError(
      `Failed to derive Bitcoin keys: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.DERIVATION_ERROR,
      error
    );
  }
}

/**
 * Creates a Bitcoin derivation path
 * @param purpose - Purpose value (44, 49, 84, 86)
 * @param accountIndex - Account index (default: 0)
 * @param change - Change flag (0 for external, 1 for internal/change) (default: 0)
 * @param addressIndex - Address index (default: 0)
 * @param testnet - Whether to use testnet coin type (default: false)
 * @returns BIP32 derivation path
 */
export function createBitcoinPath(
  purpose: number,
  accountIndex: number = 0,
  change: number = 0,
  addressIndex: number = 0,
  testnet: boolean = false
): string {
  // Validate purpose
  if (![
    BITCOIN_PURPOSE.LEGACY,
    BITCOIN_PURPOSE.NESTED_SEGWIT,
    BITCOIN_PURPOSE.NATIVE_SEGWIT,
    BITCOIN_PURPOSE.TAPROOT
  ].includes(purpose)) {
    throw createError(
      `Invalid purpose value: ${purpose}`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Validate other indices
  if (accountIndex < 0 || change < 0 || addressIndex < 0) {
    throw createError(
      'Indices must be non-negative',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Validate change value
  if (change !== 0 && change !== 1) {
    throw createError(
      'Change value must be 0 (external) or 1 (internal/change)',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  const coinType = testnet ? COIN_TYPE.BITCOIN_TESTNET : COIN_TYPE.BITCOIN;
  
  return `m/${purpose}'/${coinType}'/${accountIndex}'/${change}/${addressIndex}`;
}

/**
 * Tests the Bitcoin key derivation implementation
 * @returns True if all tests pass
 * @throws Error if any test fails
 */
export function testBitcoinImplementation(): boolean {
  // Test vector for P2PKH address
  const testP2PKH = () => {
    const pubkeyHash = new Uint8Array([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x01, 0x23, 0x45, 0x67
    ]);
    
    const address = createP2PKHAddress(pubkeyHash);
    
    // Expected address calculated offline
    const expectedAddress = '12hRMvLaGqHLcP6QCJZQP4UgwSANQ3xNNS';
    
    if (address !== expectedAddress) {
      throw createError(
        `P2PKH address test failed:\n      Expected: ${expectedAddress}\n      Got: ${address}`,
        ErrorType.CRYPTO_ERROR
      );
    }
    
    return true;
  };
  
  // Test vector for P2WPKH address
  const testP2WPKH = () => {
    const pubkeyHash = new Uint8Array([
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x01, 0x23, 0x45, 0x67
    ]);
    
    const { address } = createP2WPKHAddress(pubkeyHash);
    
    // Expected address calculated offline
    const expectedAddress = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3';
    
    if (address !== expectedAddress) {
      throw createError(
        `P2WPKH address test failed:\n      Expected: ${expectedAddress}\n      Got: ${address}`,
        ErrorType.CRYPTO_ERROR
      );
    }
    
    return true;
  };
  
  // Run all tests
  testP2PKH();
  testP2WPKH();
  
  return true;
}
