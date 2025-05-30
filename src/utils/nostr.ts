import { HDKey } from '@scure/bip32';
import { bech32 } from 'bech32';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';

import {
  NostrKeys,
  ErrorType,
  AppError,
  PathType
} from '../types';
import {
  COIN_TYPE,
  BITCOIN_PURPOSE,
  PATH_PATTERNS,
  NOSTR
} from '../constants/derivationPaths';
import {
  createError,
  safeExec,
  clearHDKey,
  createSecureArray
} from './crypto';

/**
 * Determines if a derivation path is a Nostr path
 * @param path - Derivation path to check
 * @returns True if the path is a Nostr path
 */
export function isNostrPath(path: string): boolean {
  return path.startsWith(PATH_PATTERNS.NOSTR);
}

/**
 * Validates a Nostr derivation path
 * @param path - Derivation path to check
 * @returns True if valid, false otherwise
 */
export function validateNostrPath(path: string): boolean {
  // Check if it's a Nostr path
  if (!isNostrPath(path)) {
    return false;
  }
  
  // Basic validation for BIP32 path format
  return /^m(\/\d+'?)*$/.test(path);
}

/**
 * Creates a Nostr derivation path
 * @param accountIndex - Account index (default: 0)
 * @param change - Change flag (0 for external, 1 for internal) (default: 0)
 * @param addressIndex - Address index (default: 0)
 * @returns BIP32 derivation path
 */
export function createNostrPath(
  accountIndex: number = 0,
  change: number = 0,
  addressIndex?: number
): string {
  // Validate indices
  if (accountIndex < 0 || change < 0) {
    throw createError(
      'Indices must be non-negative',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // Validate change value
  if (change !== 0 && change !== 1) {
    throw createError(
      'Change value must be 0 (external) or 1 (internal)',
      ErrorType.VALIDATION_ERROR
    );
  }
  
  // BIP44-style path: m/purpose'/coin_type'/account'/change/address_index
  const basePath = `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/${accountIndex}'/${change}`;
  
  // If address index is provided, include it in the path
  if (addressIndex !== undefined) {
    if (addressIndex < 0) {
      throw createError(
        'Address index must be non-negative',
        ErrorType.VALIDATION_ERROR
      );
    }
    return `${basePath}/${addressIndex}`;
  }
  
  return basePath;
}

/**
 * Encodes a Nostr private key as nsec
 * @param privateKey - 32-byte private key
 * @returns nsec encoded private key
 */
export function encodeNsec(privateKey: Uint8Array): string {
  if (privateKey.length !== 32) {
    throw createError(
      `Invalid private key length: ${privateKey.length} (expected 32)`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  return safeExec(
    () => bech32.encode(NOSTR.PRIVATE_KEY_HRP, bech32.toWords(privateKey)),
    ErrorType.CRYPTO_ERROR,
    'Failed to encode nsec'
  );
}

/**
 * Decodes an nsec encoded private key
 * @param nsec - nsec encoded private key
 * @returns 32-byte private key
 */
export function decodeNsec(nsec: string): Uint8Array {
  try {
    const { prefix, words } = bech32.decode(nsec);
    
    if (prefix !== NOSTR.PRIVATE_KEY_HRP) {
      throw createError(
        `Invalid prefix: ${prefix} (expected ${NOSTR.PRIVATE_KEY_HRP})`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    const privateKey = bech32.fromWords(words);
    
    if (privateKey.length !== 32) {
      throw createError(
        `Invalid private key length: ${privateKey.length} (expected 32)`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    return privateKey;
  } catch (error) {
    if ((error as AppError).type) {
      throw error;
    }
    
    throw createError(
      `Failed to decode nsec: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.VALIDATION_ERROR,
      error
    );
  }
}

/**
 * Encodes a Nostr public key as npub
 * @param publicKey - 32-byte x-only public key or 33-byte compressed public key
 * @returns npub encoded public key
 */
export function encodeNpub(publicKey: Uint8Array): string {
  // Handle both 33-byte compressed and 32-byte x-only public keys
  const xOnlyPubKey = publicKey.length === 33 ? publicKey.slice(1) : publicKey;
  
  if (xOnlyPubKey.length !== 32) {
    throw createError(
      `Invalid public key length: ${xOnlyPubKey.length} (expected 32)`,
      ErrorType.VALIDATION_ERROR
    );
  }
  
  return safeExec(
    () => bech32.encode(NOSTR.PUBLIC_KEY_HRP, bech32.toWords(xOnlyPubKey)),
    ErrorType.CRYPTO_ERROR,
    'Failed to encode npub'
  );
}

/**
 * Decodes an npub encoded public key
 * @param npub - npub encoded public key
 * @returns 32-byte x-only public key
 */
export function decodeNpub(npub: string): Uint8Array {
  try {
    const { prefix, words } = bech32.decode(npub);
    
    if (prefix !== NOSTR.PUBLIC_KEY_HRP) {
      throw createError(
        `Invalid prefix: ${prefix} (expected ${NOSTR.PUBLIC_KEY_HRP})`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    const publicKey = bech32.fromWords(words);
    
    if (publicKey.length !== 32) {
      throw createError(
        `Invalid public key length: ${publicKey.length} (expected 32)`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
    return publicKey;
  } catch (error) {
    if ((error as AppError).type) {
      throw error;
    }
    
    throw createError(
      `Failed to decode npub: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.VALIDATION_ERROR,
      error
    );
  }
}

/**
 * Derives Nostr keys from a master key and derivation path
 * @param masterKey - HDKey master key
 * @param path - BIP32 derivation path
 * @returns Nostr keys (nsec and npub)
 */
export function deriveNostrKeys(masterKey: HDKey, path: string): NostrKeys {
  try {
    // Validate the path
    if (!validateNostrPath(path) && !isNostrPath(path)) {
      throw createError(
        `Invalid Nostr derivation path: ${path}`,
        ErrorType.VALIDATION_ERROR
      );
    }
    
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
    
    // Create secure copies of the keys to avoid memory leaks
    const securePrivateKey = createSecureArray(key.privateKey);
    const securePublicKey = createSecureArray(key.publicKey);
    
    // Encode as nsec and npub
    const nsec = encodeNsec(securePrivateKey.data);
    const npub = encodeNpub(securePublicKey.data);
    
    // Clean up sensitive data
    securePrivateKey.clear();
    securePublicKey.clear();
    clearHDKey(key);
    
    return { nsec, npub };
  } catch (error) {
    if ((error as AppError).type) {
      throw error;
    }
    
    throw createError(
      `Failed to derive Nostr keys: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.DERIVATION_ERROR,
      error
    );
  }
}

/**
 * Computes a Nostr event ID
 * @param event - Nostr event object
 * @returns Event ID as a hex string
 */
export function computeEventId(event: {
  kind: number;
  created_at: number;
  tags: string[][];
  content: string;
  pubkey: string;
}): string {
  try {
    // Create a serialized event for hashing
    const serializedEvent = JSON.stringify([
      0, // Version
      event.pubkey,
      event.created_at,
      event.kind,
      event.tags,
      event.content
    ]);
    
    // Hash the serialized event
    const hash = sha256(new TextEncoder().encode(serializedEvent));
    
    return bytesToHex(hash);
  } catch (error) {
    throw createError(
      `Failed to compute event ID: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.CRYPTO_ERROR,
      error
    );
  }
}

/**
 * Signs a Nostr event
 * @param event - Nostr event object without the signature
 * @param privateKey - Private key as Uint8Array or nsec string
 * @returns Signature as a hex string
 */
export function signEvent(
  event: {
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
    pubkey: string;
  },
  privateKey: Uint8Array | string
): string {
  try {
    // Handle nsec strings
    const keyBytes = typeof privateKey === 'string' && privateKey.startsWith('nsec')
      ? decodeNsec(privateKey)
      : privateKey;
    
    // Compute the event ID
    const eventId = computeEventId(event);
    
    // TODO: Implement actual signing
    // This would require importing a Schnorr signature library
    // For now, we'll return a placeholder
    return 'signature_placeholder';
  } catch (error) {
    throw createError(
      `Failed to sign event: ${error instanceof Error ? error.message : String(error)}`,
      ErrorType.CRYPTO_ERROR,
      error
    );
  }
}

/**
 * Tests the Nostr key derivation implementation
 * @returns True if all tests pass
 * @throws Error if any test fails
 */
export function testNostrImplementation(): boolean {
  // Test nsec encoding/decoding
  const testNsecCodec = () => {
    const privateKey = new Uint8Array(32).fill(1); // 32 bytes of 0x01
    const nsec = encodeNsec(privateKey);
    const decoded = decodeNsec(nsec);
    
    // Check if the decoded key matches the original
    for (let i = 0; i < 32; i++) {
      if (decoded[i] !== privateKey[i]) {
        throw createError(
          'nsec codec test failed: decoded key does not match original',
          ErrorType.CRYPTO_ERROR
        );
      }
    }
    
    return true;
  };
  
  // Test npub encoding/decoding
  const testNpubCodec = () => {
    const publicKey = new Uint8Array(32).fill(2); // 32 bytes of 0x02
    const npub = encodeNpub(publicKey);
    const decoded = decodeNpub(npub);
    
    // Check if the decoded key matches the original
    for (let i = 0; i < 32; i++) {
      if (decoded[i] !== publicKey[i]) {
        throw createError(
          'npub codec test failed: decoded key does not match original',
          ErrorType.CRYPTO_ERROR
        );
      }
    }
    
    return true;
  };
  
  // Test path validation
  const testPathValidation = () => {
    // Valid paths
    if (!validateNostrPath(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0`)) {
      throw createError(
        'Path validation test failed: valid path rejected',
        ErrorType.VALIDATION_ERROR
      );
    }
    
    // Invalid paths
    if (validateNostrPath(`m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0`)) {
      throw createError(
        'Path validation test failed: invalid path accepted',
        ErrorType.VALIDATION_ERROR
      );
    }
    
    return true;
  };
  
  // Run all tests
  testNsecCodec();
  testNpubCodec();
  testPathValidation();
  
  return true;
}
