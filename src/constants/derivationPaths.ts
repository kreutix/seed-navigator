import { PathTemplate, BitcoinAddressType } from '../types';

/**
 * BIP32 Hardened Offset
 * Used to indicate a hardened derivation in BIP32 paths
 */
export const HARDENED_OFFSET = 0x80000000;

/**
 * Default derivation path used when initializing the application
 */
export const DEFAULT_DERIVATION_PATH = "m/84'/0'/0'/0";

/**
 * Bitcoin purpose values for different address types
 */
export const BITCOIN_PURPOSE = {
  LEGACY: 44,           // BIP44 - Legacy P2PKH
  NESTED_SEGWIT: 49,    // BIP49 - Nested SegWit P2SH-P2WPKH
  NATIVE_SEGWIT: 84,    // BIP84 - Native SegWit P2WPKH
  TAPROOT: 86           // BIP86 - Taproot P2TR
};

/**
 * Coin type values for different cryptocurrencies
 */
export const COIN_TYPE = {
  BITCOIN: 0,
  BITCOIN_TESTNET: 1,
  LITECOIN: 2,
  DOGECOIN: 3,
  ETHEREUM: 60,
  NOSTR: 1237
};

/**
 * Map of Bitcoin address types to their purpose values
 */
export const ADDRESS_TYPE_TO_PURPOSE: Record<BitcoinAddressType, number> = {
  [BitcoinAddressType.P2PKH]: BITCOIN_PURPOSE.LEGACY,
  [BitcoinAddressType.P2SH_P2WPKH]: BITCOIN_PURPOSE.NESTED_SEGWIT,
  [BitcoinAddressType.P2WPKH]: BITCOIN_PURPOSE.NATIVE_SEGWIT,
  [BitcoinAddressType.P2TR]: BITCOIN_PURPOSE.TAPROOT
};

/**
 * Map of purpose values to Bitcoin address types
 */
export const PURPOSE_TO_ADDRESS_TYPE: Record<number, BitcoinAddressType> = {
  [BITCOIN_PURPOSE.LEGACY]: BitcoinAddressType.P2PKH,
  [BITCOIN_PURPOSE.NESTED_SEGWIT]: BitcoinAddressType.P2SH_P2WPKH,
  [BITCOIN_PURPOSE.NATIVE_SEGWIT]: BitcoinAddressType.P2WPKH,
  [BITCOIN_PURPOSE.TAPROOT]: BitcoinAddressType.P2TR
};

/**
 * Path templates for Bitcoin derivation paths
 */
export const BITCOIN_PATH_TEMPLATES: PathTemplate[] = [
  { 
    label: 'Native SegWit (P2WPKH)', 
    path: `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0` 
  },
  { 
    label: 'Nested SegWit (P2SH-P2WPKH)', 
    path: `m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/0'/0` 
  },
  { 
    label: 'Legacy (P2PKH)', 
    path: `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/0'/0` 
  },
  { 
    label: 'Taproot (P2TR)', 
    path: `m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/0'/0` 
  }
];

/**
 * Path templates for Nostr derivation paths
 */
export const NOSTR_PATH_TEMPLATES: PathTemplate[] = [
  { 
    label: 'Nostr BIP-32', 
    path: `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0` 
  },
  { 
    label: 'Nostr BIP-44', 
    path: `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/0'/0/0` 
  }
];

/**
 * Combined path templates for all supported protocols
 */
export const COMMON_PATHS = {
  bitcoin: BITCOIN_PATH_TEMPLATES,
  nostr: NOSTR_PATH_TEMPLATES
};

/**
 * Path patterns for identifying different path types
 */
export const PATH_PATTERNS = {
  BITCOIN_LEGACY: `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.BITCOIN}'/`,
  BITCOIN_NESTED_SEGWIT: `m/${BITCOIN_PURPOSE.NESTED_SEGWIT}'/${COIN_TYPE.BITCOIN}'/`,
  BITCOIN_NATIVE_SEGWIT: `m/${BITCOIN_PURPOSE.NATIVE_SEGWIT}'/${COIN_TYPE.BITCOIN}'/`,
  BITCOIN_TAPROOT: `m/${BITCOIN_PURPOSE.TAPROOT}'/${COIN_TYPE.BITCOIN}'/`,
  NOSTR: `m/${BITCOIN_PURPOSE.LEGACY}'/${COIN_TYPE.NOSTR}'/`
};

/**
 * BIP85 constants for child seed derivation
 */
export const BIP85 = {
  PATH_PREFIX: "m/83696968'",  // BIP85 path prefix (83696968 is "bip" in ASCII)
  BIP39_APP_NUMBER: 39,        // BIP39 application number for BIP85
  DEFAULT_LANGUAGE: 0,         // English
  DEFAULT_WORD_COUNT: 24       // Default to 24-word mnemonics
};

/**
 * Bitcoin network constants
 */
export const BITCOIN_NETWORK = {
  MAINNET: {
    PRIVATE_KEY_VERSION: 0x80,  // Version byte for WIF private keys
    P2PKH_VERSION: 0x00,        // Version byte for P2PKH addresses
    P2SH_VERSION: 0x05,         // Version byte for P2SH addresses
    BECH32_HRP: 'bc'            // Human-readable part for Bech32 addresses
  },
  TESTNET: {
    PRIVATE_KEY_VERSION: 0xEF,  // Version byte for testnet WIF private keys
    P2PKH_VERSION: 0x6F,        // Version byte for testnet P2PKH addresses
    P2SH_VERSION: 0xC4,         // Version byte for testnet P2SH addresses
    BECH32_HRP: 'tb'            // Human-readable part for testnet Bech32 addresses
  }
};

/**
 * Script operation codes used in Bitcoin transactions
 */
export const BITCOIN_SCRIPT_OPS = {
  OP_0: 0x00,
  OP_PUSHBYTES_20: 0x14,
  OP_PUSHBYTES_32: 0x20,
  OP_1: 0x51
};

/**
 * Witness program prefixes for different address types
 */
export const WITNESS_PROGRAM_PREFIXES = {
  P2WPKH: '0014',  // OP_0 + OP_PUSHBYTES_20
  P2TR: '5120'     // OP_1 + OP_PUSHBYTES_32
};

/**
 * Nostr constants
 */
export const NOSTR = {
  PRIVATE_KEY_HRP: 'nsec',  // Human-readable part for private keys
  PUBLIC_KEY_HRP: 'npub'    // Human-readable part for public keys
};

/**
 * Default values for the application
 */
export const DEFAULTS = {
  DERIVATION_PATH: DEFAULT_DERIVATION_PATH,
  MNEMONIC_STRENGTH: 256,  // 256 bits = 24 words
  COPY_TIMEOUT: 2000       // 2 seconds for copy success message
};
