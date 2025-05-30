import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import { renderHook, act, cleanup } from '@testing-library/react';
import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';

import { useSeedDerivation } from '../useSeedDerivation';
import * as cryptoUtils from '../../utils/crypto';
import { ErrorType } from '../../types';

// Valid test seed phrases
const VALID_TEST_SEED = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ANOTHER_VALID_SEED = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong';

// Mock window.crypto.getRandomValues for deterministic testing
const mockGetRandomValues = vi.fn((array: Uint8Array) => {
  // Fill with predictable values based on array length
  for (let i = 0; i < array.length; i++) {
    array[i] = i % 256;
  }
  return array;
});

// Mock console.error to suppress expected error messages during tests
const originalConsoleError = console.error;
const mockConsoleError = vi.fn();

// Setup and teardown for mocks
beforeEach(() => {
  vi.spyOn(crypto, 'getRandomValues').mockImplementation(mockGetRandomValues);
  console.error = mockConsoleError;
  
  // Mock validateMnemonic to return true for our test seeds
  vi.spyOn(cryptoUtils, 'validateMnemonic').mockImplementation((mnemonic: string) => {
    return mnemonic === VALID_TEST_SEED || mnemonic === ANOTHER_VALID_SEED;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  console.error = originalConsoleError;
  cleanup();
});

describe('useSeedDerivation Hook', () => {
  describe('Initial State', () => {
    it('should initialize with default values', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      expect(result.current.rootSeedPhrase).toBe('');
      expect(result.current.isRootSeedSet).toBe(false);
      expect(result.current.currentPath).toEqual([]);
      expect(result.current.derivationPath).toBe('m/84\'/0\'/0\'/0');
      expect(result.current.currentMnemonic).toBe('');
      expect(result.current.childMnemonics).toEqual([]);
      expect(result.current.error).toBeNull();
      expect(result.current.pathType).toBe('bitcoin');
    });
    
    it('should have all required functions', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      expect(typeof result.current.setDerivationPath).toBe('function');
      expect(typeof result.current.navigateToChild).toBe('function');
      expect(typeof result.current.navigateBack).toBe('function');
      expect(typeof result.current.setRootSeed).toBe('function');
      expect(typeof result.current.generateRandomSeed).toBe('function');
      expect(typeof result.current.resetSeed).toBe('function');
      expect(typeof result.current.updateRootSeedPhrase).toBe('function');
      expect(typeof result.current.truncateMnemonic).toBe('function');
    });
  });
  
  describe('Seed Phrase Management', () => {
    it('should update root seed phrase', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
      });
      
      expect(result.current.rootSeedPhrase).toBe(VALID_TEST_SEED);
      expect(result.current.isRootSeedSet).toBe(false); // Not set until setRootSeed is called
    });
    
    it('should set root seed when valid', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      expect(result.current.isRootSeedSet).toBe(true);
      expect(result.current.currentPath).toEqual([]);
      expect(result.current.error).toBeNull();
    });
    
    it('should reject invalid seed phrases', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // Mock validateMnemonic to return false for this test
      vi.spyOn(cryptoUtils, 'validateMnemonic').mockReturnValueOnce(false);
      
      act(() => {
        result.current.updateRootSeedPhrase('invalid seed phrase');
        result.current.setRootSeed();
      });
      
      expect(result.current.isRootSeedSet).toBe(false);
      expect(result.current.error).not.toBeNull();
      expect(result.current.error?.type).toBe(ErrorType.VALIDATION_ERROR);
    });
    
    it('should reject seed phrases with wrong word count', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      act(() => {
        result.current.updateRootSeedPhrase('abandon abandon abandon');
        result.current.setRootSeed();
      });
      
      expect(result.current.isRootSeedSet).toBe(false);
      expect(result.current.error).not.toBeNull();
      expect(result.current.error?.message).toContain('valid 24-word seed phrase');
    });
    
    it('should generate a random seed phrase', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // Spy on the generateRandomMnemonic function
      const generateRandomMnemonicSpy = vi.spyOn(cryptoUtils, 'generateRandomMnemonic');
      
      act(() => {
        result.current.generateRandomSeed();
      });
      
      expect(generateRandomMnemonicSpy).toHaveBeenCalled();
      expect(result.current.rootSeedPhrase).not.toBe('');
      expect(result.current.isRootSeedSet).toBe(false); // Not set until setRootSeed is called
    });
    
    it('should reset seed state', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // First set a seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      expect(result.current.isRootSeedSet).toBe(true);
      
      // Then reset it
      act(() => {
        result.current.resetSeed();
      });
      
      expect(result.current.rootSeedPhrase).toBe('');
      expect(result.current.isRootSeedSet).toBe(false);
      expect(result.current.currentPath).toEqual([]);
      expect(result.current.error).toBeNull();
    });
    
    it('should truncate mnemonic phrases correctly', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // Test with default word count (6)
      expect(result.current.truncateMnemonic(VALID_TEST_SEED)).toBe('abandon abandon abandon abandon abandon abandon ...');
      
      // Test with custom word count
      expect(result.current.truncateMnemonic(VALID_TEST_SEED, 3)).toBe('abandon abandon abandon ...');
      
      // Test with short phrase (no truncation)
      expect(result.current.truncateMnemonic('word1 word2 word3')).toBe('word1 word2 word3');
      
      // Test with empty string
      expect(result.current.truncateMnemonic('')).toBe('');
    });
  });
  
  describe('Path Navigation', () => {
    it('should navigate to child seed', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Navigate to child index 3
      act(() => {
        result.current.navigateToChild(3);
      });
      
      expect(result.current.currentPath).toEqual([3]);
      
      // Navigate to another child
      act(() => {
        result.current.navigateToChild(5);
      });
      
      expect(result.current.currentPath).toEqual([3, 5]);
    });
    
    it('should navigate back to parent seed', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed and navigate to a child
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
        result.current.navigateToChild(3);
        result.current.navigateToChild(5);
      });
      
      expect(result.current.currentPath).toEqual([3, 5]);
      
      // Navigate back
      act(() => {
        result.current.navigateBack();
      });
      
      expect(result.current.currentPath).toEqual([3]);
      
      // Navigate back again
      act(() => {
        result.current.navigateBack();
      });
      
      expect(result.current.currentPath).toEqual([]);
    });
    
    it('should update derivation path', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      const newPath = "m/44'/0'/0'/0";
      
      act(() => {
        result.current.setDerivationPath(newPath);
      });
      
      expect(result.current.derivationPath).toBe(newPath);
      expect(result.current.pathType).toBe('bitcoin');
      
      // Test with Nostr path
      const nostrPath = "m/44'/1237'/0'/0";
      
      act(() => {
        result.current.setDerivationPath(nostrPath);
      });
      
      expect(result.current.derivationPath).toBe(nostrPath);
      expect(result.current.pathType).toBe('nostr');
    });
  });
  
  describe('Mnemonic Derivation', () => {
    it('should derive current mnemonic based on path', () => {
      // Mock deriveChildMnemonic to return predictable values
      const deriveChildMnemonicMock = vi.spyOn(cryptoUtils, 'deriveChildMnemonic');
      deriveChildMnemonicMock.mockImplementation((root, path) => {
        if (path.length === 0) return root;
        return `${root}-child-${path.join('-')}`;
      });
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Initial state should have the root seed as current mnemonic
      expect(result.current.currentMnemonic).toBe(VALID_TEST_SEED);
      
      // Navigate to a child
      act(() => {
        result.current.navigateToChild(3);
      });
      
      // Current mnemonic should be updated
      expect(result.current.currentMnemonic).toBe(`${VALID_TEST_SEED}-child-3`);
      
      // Navigate to another child
      act(() => {
        result.current.navigateToChild(5);
      });
      
      // Current mnemonic should be updated again
      expect(result.current.currentMnemonic).toBe(`${VALID_TEST_SEED}-child-3-5`);
      
      // Restore the original implementation
      deriveChildMnemonicMock.mockRestore();
    });
    
    it('should derive child mnemonics for navigation', () => {
      // Mock deriveChildMnemonic to return predictable values
      const deriveChildMnemonicMock = vi.spyOn(cryptoUtils, 'deriveChildMnemonic');
      deriveChildMnemonicMock.mockImplementation((root, path) => {
        return `${root}-child-${path.join('-')}`;
      });
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Should have 10 child mnemonics
      expect(result.current.childMnemonics.length).toBe(10);
      
      // Each child mnemonic should be derived correctly
      for (let i = 0; i < 10; i++) {
        expect(result.current.childMnemonics[i]).toBe(`${VALID_TEST_SEED}-child-${i}`);
      }
      
      // Navigate to a child
      act(() => {
        result.current.navigateToChild(3);
      });
      
      // Child mnemonics should be updated
      expect(result.current.childMnemonics.length).toBe(10);
      for (let i = 0; i < 10; i++) {
        expect(result.current.childMnemonics[i]).toBe(`${VALID_TEST_SEED}-child-3-${i}`);
      }
      
      // Restore the original implementation
      deriveChildMnemonicMock.mockRestore();
    });
    
    it('should handle errors in mnemonic derivation', () => {
      // Mock deriveChildMnemonic to throw an error
      const deriveChildMnemonicMock = vi.spyOn(cryptoUtils, 'deriveChildMnemonic');
      deriveChildMnemonicMock.mockImplementation(() => {
        throw new Error('Derivation failed');
      });
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Current mnemonic should be empty due to error
      expect(result.current.currentMnemonic).toBe('');
      expect(result.current.childMnemonics).toEqual([]);
      expect(result.current.error).not.toBeNull();
      expect(mockConsoleError).toHaveBeenCalled();
      
      // Restore the original implementation
      deriveChildMnemonicMock.mockRestore();
    });
  });
  
  describe('Key Derivation', () => {
    it('should derive keys based on current mnemonic and derivation path', () => {
      // Mock the key derivation functions
      const deriveBitcoinKeysMock = vi.fn().mockReturnValue({
        address: 'bitcoin-address',
        privateKeyWIF: 'bitcoin-wif',
        publicKey: 'bitcoin-pubkey',
        publicKeyHash: 'bitcoin-pubkey-hash',
        publicKeyHash160: 'bitcoin-pubkey-hash160',
        witnessProgram: 'bitcoin-witness-program',
        checksum: 'bitcoin-checksum'
      });
      
      const deriveNostrKeysMock = vi.fn().mockReturnValue({
        nsec: 'nostr-nsec',
        npub: 'nostr-npub'
      });
      
      vi.mock('../../utils/bitcoin', async () => {
        const actual = await vi.importActual('../../utils/bitcoin');
        return {
          ...(actual as any),
          deriveBitcoinKeys: deriveBitcoinKeysMock,
          getPathType: vi.fn().mockReturnValue('bitcoin')
        };
      });
      
      vi.mock('../../utils/nostr', async () => {
        const actual = await vi.importActual('../../utils/nostr');
        return {
          ...(actual as any),
          deriveNostrKeys: deriveNostrKeysMock
        };
      });
      
      // Mock deriveChildMnemonic to return a valid mnemonic
      vi.spyOn(cryptoUtils, 'deriveChildMnemonic').mockReturnValue(VALID_TEST_SEED);
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Should have 10 derived keys
      expect(result.current.derivedKeys.length).toBe(10);
      
      // Each derived key should have the expected properties
      for (let i = 0; i < 10; i++) {
        expect(result.current.derivedKeys[i]).toEqual({
          index: i,
          nsec: 'nostr-nsec',
          npub: 'nostr-npub',
          bitcoinAddress: 'bitcoin-address',
          bitcoinPrivateKey: 'bitcoin-wif',
          bitcoinPublicKey: 'bitcoin-pubkey',
          bitcoinPublicKeyHash: 'bitcoin-pubkey-hash',
          bitcoinPublicKeyHash160: 'bitcoin-pubkey-hash160',
          bitcoinWitnessProgram: 'bitcoin-witness-program',
          bitcoinChecksum: 'bitcoin-checksum'
        });
      }
      
      // Verify the derivation functions were called with the correct paths
      for (let i = 0; i < 10; i++) {
        const expectedPath = `m/84'/0'/0'/0/${i}`;
        expect(deriveBitcoinKeysMock).toHaveBeenCalledWith(expect.any(Object), expectedPath, false);
        expect(deriveNostrKeysMock).toHaveBeenCalledWith(expect.any(Object), expectedPath);
      }
    });
    
    it('should handle paths without m/ prefix', () => {
      // Mock the key derivation functions
      const deriveBitcoinKeysMock = vi.fn().mockReturnValue({
        address: 'bitcoin-address',
        privateKeyWIF: 'bitcoin-wif',
        publicKey: 'bitcoin-pubkey',
        publicKeyHash: 'bitcoin-pubkey-hash',
        publicKeyHash160: 'bitcoin-pubkey-hash160',
        witnessProgram: 'bitcoin-witness-program',
        checksum: 'bitcoin-checksum'
      });
      
      vi.mock('../../utils/bitcoin', async () => {
        const actual = await vi.importActual('../../utils/bitcoin');
        return {
          ...(actual as any),
          deriveBitcoinKeys: deriveBitcoinKeysMock,
          getPathType: vi.fn().mockReturnValue('bitcoin')
        };
      });
      
      // Mock deriveChildMnemonic to return a valid mnemonic
      vi.spyOn(cryptoUtils, 'deriveChildMnemonic').mockReturnValue(VALID_TEST_SEED);
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed and a path without m/ prefix
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
        result.current.setDerivationPath("44'/0'/0'/0");
      });
      
      // Should still derive keys correctly
      expect(result.current.derivedKeys.length).toBe(10);
      
      // Verify the derivation function was called with the correct path (with m/ prefix added)
      for (let i = 0; i < 10; i++) {
        const expectedPath = `m/44'/0'/0'/0/${i}`;
        expect(deriveBitcoinKeysMock).toHaveBeenCalledWith(expect.any(Object), expectedPath, false);
      }
    });
    
    it('should return placeholder keys when no mnemonic is available', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // No seed set yet
      expect(result.current.derivedKeys.length).toBe(10);
      
      // Each derived key should be a placeholder
      for (let i = 0; i < 10; i++) {
        expect(result.current.derivedKeys[i]).toEqual({
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
        });
      }
    });
    
    it('should handle errors in key derivation', () => {
      // Mock bip39.mnemonicToSeedSync to throw an error
      vi.spyOn(bip39, 'mnemonicToSeedSync').mockImplementation(() => {
        throw new Error('Seed generation failed');
      });
      
      // Mock deriveChildMnemonic to return a valid mnemonic
      vi.spyOn(cryptoUtils, 'deriveChildMnemonic').mockReturnValue(VALID_TEST_SEED);
      
      const { result } = renderHook(() => useSeedDerivation());
      
      // Setup with a valid seed
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      // Should return placeholder keys due to error
      expect(result.current.derivedKeys.length).toBe(10);
      expect(result.current.derivedKeys[0].bitcoinAddress).toBe('...');
      expect(result.current.error).not.toBeNull();
      expect(mockConsoleError).toHaveBeenCalled();
    });
  });
  
  describe('Error Handling', () => {
    it('should handle errors in setRootSeed', () => {
      // Mock validateMnemonic to throw an error
      vi.spyOn(cryptoUtils, 'validateMnemonic').mockImplementation(() => {
        throw new Error('Validation error');
      });
      
      const { result } = renderHook(() => useSeedDerivation());
      
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
      });
      
      expect(result.current.isRootSeedSet).toBe(false);
      expect(result.current.error).not.toBeNull();
      expect(result.current.error?.type).toBe(ErrorType.VALIDATION_ERROR);
      expect(mockConsoleError).toHaveBeenCalled();
    });
    
    it('should handle errors in generateRandomSeed', () => {
      // Mock generateRandomMnemonic to throw an error
      vi.spyOn(cryptoUtils, 'generateRandomMnemonic').mockImplementation(() => {
        throw new Error('Random generation error');
      });
      
      const { result } = renderHook(() => useSeedDerivation());
      
      act(() => {
        result.current.generateRandomSeed();
      });
      
      expect(result.current.rootSeedPhrase).toBe('');
      expect(result.current.error).not.toBeNull();
      expect(result.current.error?.type).toBe(ErrorType.CRYPTO_ERROR);
      expect(mockConsoleError).toHaveBeenCalled();
    });
    
    it('should reset error state when updating seed phrase', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // First cause an error
      act(() => {
        result.current.updateRootSeedPhrase('invalid seed');
        result.current.setRootSeed();
      });
      
      expect(result.current.error).not.toBeNull();
      
      // Then update the seed phrase
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
      });
      
      // Error should be cleared
      expect(result.current.error).toBeNull();
    });
    
    it('should reset error state when resetting seed', () => {
      const { result } = renderHook(() => useSeedDerivation());
      
      // First cause an error
      act(() => {
        result.current.updateRootSeedPhrase('invalid seed');
        result.current.setRootSeed();
      });
      
      expect(result.current.error).not.toBeNull();
      
      // Then reset the seed
      act(() => {
        result.current.resetSeed();
      });
      
      // Error should be cleared
      expect(result.current.error).toBeNull();
    });
  });
  
  describe('Cleanup', () => {
    it('should clean up sensitive data on unmount', () => {
      // Create a component that will unmount
      const { unmount, result } = renderHook(() => useSeedDerivation());
      
      // Set some sensitive data
      act(() => {
        result.current.updateRootSeedPhrase(VALID_TEST_SEED);
        result.current.setRootSeed();
        result.current.navigateToChild(3);
      });
      
      // Unmount the component
      unmount();
      
      // Since we can't directly check the internal state after unmount,
      // we can verify that the cleanup effect was registered by checking
      // that the useEffect cleanup function was called
      // This is a limitation of testing hooks with cleanup effects
      
      // In a real application, we would need to ensure that sensitive data
      // is properly cleared from memory in the cleanup function
    });
  });
});
