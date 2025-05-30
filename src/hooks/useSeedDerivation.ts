import { useState, useMemo, useCallback, useEffect } from 'react';
import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { wordlist } from '@scure/bip39/wordlists/english';

import { 
  deriveChildMnemonic,
  validateMnemonic, 
  generateRandomMnemonic, 
  createError,
  clearHDKey
} from '../utils/crypto';
import { deriveBitcoinKeys, getPathType } from '../utils/bitcoin';
import { deriveNostrKeys } from '../utils/nostr';
import { 
  DEFAULTS,
  DEFAULT_DERIVATION_PATH
} from '../constants/derivationPaths';
import { 
  DerivedKeys, 
  PathType, 
  ErrorType,
  AppError
} from '../types';

export interface SeedDerivationState {
  // Core state
  rootSeedPhrase: string;
  isRootSeedSet: boolean;
  currentPath: number[];
  derivationPath: string;
  
  // Derived values
  currentMnemonic: string;
  childMnemonics: string[];
  derivedKeys: DerivedKeys[];
  pathType: PathType;
  
  // Error state
  error: AppError | null;
  
  // Functions
  setDerivationPath: (path: string) => void;
  navigateToChild: (index: number) => void;
  navigateBack: () => void;
  setRootSeed: () => void;
  generateRandomSeed: () => void;
  resetSeed: () => void;
  updateRootSeedPhrase: (phrase: string) => void;
  
  // Utility functions
  truncateMnemonic: (mnemonic: string, wordCount?: number) => string;
}

/**
 * Custom hook for managing seed phrase derivation and key generation
 * 
 * Handles state management for:
 * - Root seed phrase
 * - Current derivation path
 * - Generated keys and addresses
 * 
 * @returns SeedDerivationState object with all state and functions
 */
export function useSeedDerivation(): SeedDerivationState {
  // Core state
  const [rootSeedPhrase, setRootSeedPhrase] = useState<string>('');
  const [isRootSeedSet, setIsRootSeedSet] = useState<boolean>(false);
  const [currentPath, setCurrentPath] = useState<number[]>([]);
  const [derivationPath, setDerivationPath] = useState<string>(DEFAULT_DERIVATION_PATH);
  
  // Error state
  const [error, setError] = useState<AppError | null>(null);

  /**
   * Derive the current mnemonic based on the root seed and path
   */
  const currentMnemonic = useMemo(() => {
    if (!rootSeedPhrase) return '';
    
    try {
      return deriveChildMnemonic(rootSeedPhrase, currentPath);
    } catch (err) {
      const error = err as Error;
      console.error('Error deriving mnemonic:', error);
      setError(createError(
        `Failed to derive mnemonic: ${error.message}`,
        ErrorType.DERIVATION_ERROR,
        error
      ));
      return '';
    }
  }, [rootSeedPhrase, currentPath]);

  /**
   * Derive child mnemonics for navigation
   */
  const childMnemonics = useMemo(() => {
    if (!rootSeedPhrase) return [];
    
    try {
      return Array.from({ length: 10 }, (_, i) => {
        return deriveChildMnemonic(rootSeedPhrase, [...currentPath, i]);
      });
    } catch (err) {
      const error = err as Error;
      console.error('Error deriving child mnemonics:', error);
      setError(createError(
        `Failed to derive child mnemonics: ${error.message}`,
        ErrorType.DERIVATION_ERROR,
        error
      ));
      return [];
    }
  }, [rootSeedPhrase, currentPath]);

  /**
   * Derive keys based on the current mnemonic and derivation path
   */
  const derivedKeys = useMemo(() => {
    try {
      if (currentMnemonic) {
        // Normal case - derive keys from the current mnemonic
        const seed = bip39.mnemonicToSeedSync(currentMnemonic);
        const masterKey = HDKey.fromMasterSeed(seed);
        
        const result = Array.from({ length: 10 }, (_, i) => {
          // Ensure path starts with "m/" and append index
          const path = derivationPath.startsWith('m/') ? 
            `${derivationPath}/${i}` : 
            `m/${derivationPath}/${i}`;

          const nostrKeys = deriveNostrKeys(masterKey, path);
          const bitcoinKeys = deriveBitcoinKeys(masterKey, path);
          
          return {
            index: i,
            nsec: nostrKeys.nsec,
            npub: nostrKeys.npub,
            bitcoinAddress: bitcoinKeys.address,
            bitcoinPrivateKey: bitcoinKeys.privateKeyWIF,
            bitcoinPublicKey: bitcoinKeys.publicKey,
            bitcoinPublicKeyHash: bitcoinKeys.publicKeyHash,
            bitcoinPublicKeyHash160: bitcoinKeys.publicKeyHash160,
            bitcoinWitnessProgram: bitcoinKeys.witnessProgram,
            bitcoinChecksum: bitcoinKeys.checksum
          };
        });
        
        // Clean up sensitive data
        clearHDKey(masterKey);
        
        return result;
      } else {
        // Fallback case - create 10 placeholder keys to prevent layout jumping
        return Array.from({ length: 10 }, (_, i) => ({
          index: i,
          nsec: '...',
          npub: '...',
          bitcoinAddress: '...',
          bitcoinPrivateKey: '...',
          bitcoinPublicKey: '...',
          bitcoinPublicKeyHash: '...',
          bitcoinPublicKeyHash160: '...',
          bitcoinWitnessProgram: '...',
          bitcoinChecksum: '...'
        }));
      }
    } catch (err) {
      const error = err as Error;
      console.error('Error deriving keys:', error);
      setError(createError(
        `Failed to derive keys: ${error.message}`,
        ErrorType.DERIVATION_ERROR,
        error
      ));
      
      // Even on error, return 10 placeholders to prevent layout jumping
      return Array.from({ length: 10 }, (_, i) => ({
        index: i,
        nsec: '...',
        npub: '...',
        bitcoinAddress: '...',
        bitcoinPrivateKey: '...',
        bitcoinPublicKey: '...',
        bitcoinPublicKeyHash: '...',
        bitcoinPublicKeyHash160: '...',
        bitcoinWitnessProgram: '...',
        bitcoinChecksum: '...'
      }));
    }
  }, [currentMnemonic, derivationPath]);

  /**
   * Determine the path type (bitcoin or nostr)
   */
  const pathType = useMemo(() => {
    return getPathType(derivationPath);
  }, [derivationPath]);

  /**
   * Update the root seed phrase input
   */
  const updateRootSeedPhrase = useCallback((phrase: string) => {
    setRootSeedPhrase(phrase);
    // Reset any previous errors when updating the seed phrase
    setError(null);
  }, []);

  /**
   * Set the root seed after validation
   */
  const setRootSeed = useCallback(() => {
    if (!rootSeedPhrase.trim()) return;
    
    try {
      const words = rootSeedPhrase.trim().split(/\s+/);
      if (words.length !== 24) {
        setError(createError(
          'Please enter a valid 24-word seed phrase',
          ErrorType.VALIDATION_ERROR
        ));
        return;
      }
      
      if (!validateMnemonic(rootSeedPhrase)) {
        setError(createError(
          'Invalid BIP39 seed phrase',
          ErrorType.VALIDATION_ERROR
        ));
        return;
      }
      
      setCurrentPath([]);
      setIsRootSeedSet(true);
      setError(null);
    } catch (err) {
      const error = err as Error;
      console.error('Error setting root seed:', error);
      setError(createError(
        `Invalid seed phrase: ${error.message}`,
        ErrorType.VALIDATION_ERROR,
        error
      ));
    }
  }, [rootSeedPhrase]);

  /**
   * Generate a random seed phrase
   */
  const generateRandomSeed = useCallback(() => {
    try {
      const newSeed = generateRandomMnemonic(DEFAULTS.MNEMONIC_STRENGTH);
      setRootSeedPhrase(newSeed);
      setError(null);
      // Do NOT set isRootSeedSet here - only update the textarea
    } catch (err) {
      const error = err as Error;
      console.error('Error generating random seed:', error);
      setError(createError(
        `Failed to generate random seed: ${error.message}`,
        ErrorType.CRYPTO_ERROR,
        error
      ));
    }
  }, []);

  /**
   * Reset the seed state
   */
  const resetSeed = useCallback(() => {
    setIsRootSeedSet(false);
    setRootSeedPhrase('');
    setCurrentPath([]);
    setError(null);
  }, []);

  /**
   * Navigate to a child seed
   */
  const navigateToChild = useCallback((index: number) => {
    setCurrentPath(prevPath => [...prevPath, index]);
  }, []);

  /**
   * Navigate back one level
   */
  const navigateBack = useCallback(() => {
    setCurrentPath(prevPath => prevPath.slice(0, -1));
  }, []);

  /**
   * Truncate a mnemonic phrase for display
   */
  const truncateMnemonic = useCallback((mnemonic: string, wordCount: number = 6): string => {
    if (!mnemonic) return '';
    const words = mnemonic.split(' ');
    if (words.length <= wordCount) return mnemonic;
    return words.slice(0, wordCount).join(' ') + ' ...';
  }, []);

  // Clean up sensitive data when component unmounts
  useEffect(() => {
    return () => {
      // Clear sensitive data from memory when the component unmounts
      setRootSeedPhrase('');
      setCurrentPath([]);
    };
  }, []);

  return {
    // Core state
    rootSeedPhrase,
    isRootSeedSet,
    currentPath,
    derivationPath,
    
    // Derived values
    currentMnemonic,
    childMnemonics,
    derivedKeys,
    pathType,
    
    // Error state
    error,
    
    // Functions
    setDerivationPath,
    navigateToChild,
    navigateBack,
    setRootSeed,
    generateRandomSeed,
    resetSeed,
    updateRootSeedPhrase,
    
    // Utility functions
    truncateMnemonic
  };
}
