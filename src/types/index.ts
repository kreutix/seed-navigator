import { z } from 'zod';
import { HDKey } from '@scure/bip32';

// ==============================
// Basic Types and Enums
// ==============================

/**
 * Supported path types in the application
 */
export enum PathTypeEnum {
  BITCOIN = 'bitcoin',
  NOSTR = 'nostr',
  UNKNOWN = 'unknown'
}

export type PathType = keyof typeof PathTypeEnum;

/**
 * Bitcoin address types
 */
export enum BitcoinAddressType {
  P2PKH = 'P2PKH',       // Legacy
  P2SH_P2WPKH = 'P2SH-P2WPKH', // Nested SegWit
  P2WPKH = 'P2WPKH',     // Native SegWit
  P2TR = 'P2TR'          // Taproot
}

/**
 * BIP85 application numbers and configurations
 */
export const BIP85_APPLICATIONS = {
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

// ==============================
// Key and Derivation Types
// ==============================

/**
 * Nostr key pair
 */
export interface NostrKeys {
  nsec: string; // Private key in bech32 format
  npub: string; // Public key in bech32 format
}

/**
 * Bitcoin key and address information
 */
export interface BitcoinKeys {
  address: string;
  privateKeyWIF: string;
  publicKey: string;
  publicKeyHash: string;
  publicKeyHash160: string;
  witnessProgram: string;
  checksum: string;
}

/**
 * Combined derived keys for display
 */
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

/**
 * Derivation path representation
 */
export interface DerivationPath {
  full: string;       // Full path string (e.g., "m/44'/0'/0'/0")
  segments: number[]; // Path segments including hardening info
  type: PathType;     // Path type (bitcoin, nostr, unknown)
  addressType?: BitcoinAddressType; // For Bitcoin paths
}

// ==============================
// Component Prop Types
// ==============================

export interface CopyButtonProps {
  text: string;
  className?: string;
}

export interface DerivationPathSelectorProps {
  value: string;
  onChange: (path: string) => void;
}

export interface DerivedKeyCardProps {
  keys: DerivedKeys;
  type: 'bitcoin' | 'nostr';
}

export interface KeyFieldProps {
  label?: string;
  value: string;
  index?: number;
  variant: 'main' | 'detail';
  toggleDetails?: () => void;
  showDetailsButton?: boolean;
  showDetails?: boolean;
}

export interface PathTemplate {
  label: string;
  path: string;
}

// ==============================
// Error Types
// ==============================

export enum ErrorType {
  VALIDATION_ERROR = 'ValidationError',
  DERIVATION_ERROR = 'DerivationError',
  CRYPTO_ERROR = 'CryptoError',
  CLIPBOARD_ERROR = 'ClipboardError',
  UNKNOWN_ERROR = 'UnknownError'
}

export interface AppError extends Error {
  type: ErrorType;
  details?: unknown;
}

// ==============================
// Zod Validation Schemas
// ==============================

/**
 * Schema for validating a BIP39 mnemonic phrase
 */
export const mnemonicSchema = z.string().refine(
  (mnemonic) => {
    const words = mnemonic.trim().split(/\s+/);
    return [12, 15, 18, 21, 24].includes(words.length);
  },
  {
    message: 'Mnemonic must be 12, 15, 18, 21, or 24 words',
  }
);

/**
 * Schema for validating a BIP32 derivation path
 */
export const derivationPathSchema = z.string().refine(
  (path) => {
    // Basic validation for derivation path format
    return /^m(\/\d+'?)*$/.test(path);
  },
  {
    message: 'Invalid derivation path format',
  }
);

/**
 * Schema for validating BIP85 parameters
 */
export const bip85ParamsSchema = z.object({
  index: z.number().int().min(0).max(0x7FFFFFFF),
  language: z.number().int().min(0).max(9).default(0),
  words: z.union([
    z.literal(12),
    z.literal(15),
    z.literal(18),
    z.literal(21),
    z.literal(24)
  ]).default(12)
});

// ==============================
// Utility Types
// ==============================

/**
 * Type for a function that derives a mnemonic from a root seed and path
 */
export type MnemonicDerivationFn = (
  rootSeedPhrase: string,
  path: number[]
) => string;

/**
 * Type for a function that derives Bitcoin keys from an HDKey and path
 */
export type BitcoinKeyDerivationFn = (
  masterKey: HDKey,
  path: string
) => BitcoinKeys;

/**
 * Type for a function that derives Nostr keys from an HDKey and path
 */
export type NostrKeyDerivationFn = (
  masterKey: HDKey,
  path: string
) => NostrKeys;

/**
 * Type for a function that determines the path type
 */
export type PathTypeDeterminationFn = (
  path: string
) => PathType;

/**
 * Type for secure data that should be cleared from memory
 */
export interface SecureData {
  clear: () => void;
}
