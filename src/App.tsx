import React, { useState, useMemo } from 'react';
import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
// import * as bitcoin from 'bitcoinjs-lib';
import { wordlist } from '@scure/bip39/wordlists/english';

// Function to derive the current mnemonic based on the root seed and path
const deriveCurrentMnemonic = (rootMnemonic: string, path: number[]): string => {
  const seed = bip39.mnemonicToSeedSync(rootMnemonic);
  const masterKey = HDKey.fromMasterSeed(seed);
  const derivedKey = masterKey.derive(`m/${path.join('/')}`);
  const childSeed = derivedKey.privateKey;
  return bip39.entropyToMnemonic(childSeed!.slice(0, 16), wordlist); // Use first 16 bytes for 12-word mnemonic
};

const App: React.FC = () => {
  // State variables
  const [rootSeedPhrase, setRootSeedPhrase] = useState('');
  const [currentPath, setCurrentPath] = useState<number[]>([]);
  const [derivationPath, setDerivationPath] = useState("m/84'/0'/0'/0");

  // Compute current mnemonic based on root seed and path
  const currentMnemonic = useMemo(() => {
    if (!rootSeedPhrase) return '';
    try {
      return deriveCurrentMnemonic(rootSeedPhrase, currentPath);
    } catch (error) {
      console.error('Error deriving mnemonic:', error);
      return '';
    }
  }, [rootSeedPhrase, currentPath]);

  // Derive 10 child seed phrases from the current mnemonic
  const childMnemonics = useMemo(() => {
    if (!currentMnemonic) return [];
    try {
      return Array.from({ length: 10 }, (_, i) => {
        return deriveCurrentMnemonic(currentMnemonic, [i]);
      });
    } catch (error) {
      console.error('Error deriving child mnemonics:', error);
      return [];
    }
  }, [currentMnemonic]);

  // Comment out the addresses derivation
  /*
  const addresses = useMemo(() => {
    if (!currentMnemonic) return [];
    try {
      const seed = bip39.mnemonicToSeedSync(currentMnemonic);
      const masterKey = HDKey.fromMasterSeed(seed);
      const basePath = derivationPath;
      return Array.from({ length: 10 }, (_, i) => {
        const path = `${basePath}/${i}`;
        const key = masterKey.derive(path);
        const { address } = bitcoin.payments.p2wpkh({ pubkey: key.publicKey });
        return address || '';
      });
    } catch (error) {
      console.error('Error deriving addresses:', error);
      return [];
    }
  }, [currentMnemonic, derivationPath]);
  */

  // Format the current path for display
  const pathString = `root/${currentPath.join('/')}${currentPath.length > 0 ? '/' : ''}`;

  // Handlers
  const handleSetRootSeed = () => {
    if (!rootSeedPhrase.trim()) return;
    try {
      // Validate the mnemonic
      if (!bip39.validateMnemonic(rootSeedPhrase, wordlist)) {
        alert('Invalid mnemonic phrase');
        return;
      }
      setCurrentPath([]); // Reset path when setting new seed
    } catch (error) {
      console.error('Error setting root seed:', error);
      alert('Invalid mnemonic phrase');
    }
  };

  const handleLoadChild = (index: number) => {
    setCurrentPath([...currentPath, index]); // Append child index to path
  };

  const handleBack = () => {
    setCurrentPath(currentPath.slice(0, -1)); // Remove last index to go back
  };

  // Render input form if no root seed is set
  if (!rootSeedPhrase) {
    return (
      <div className="p-4 max-w-2xl mx-auto">
        <h1 className="text-2xl font-bold mb-4">BIP32 HD Wallet Tool</h1>
        <textarea
          className="w-full p-2 border rounded mb-2"
          rows={3}
          placeholder="Enter BIP39 seed phrase"
          value={rootSeedPhrase}
          onChange={(e) => setRootSeedPhrase(e.target.value.trim())}
        />
        <button
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
          onClick={handleSetRootSeed}
        >
          Set Root Seed
        </button>
      </div>
    );
  }

  // Render main UI
  return (
    <div className="p-4 max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">BIP32 HD Wallet Tool</h1>
      <div className="mb-4">
        <span className="font-semibold">Current Path: </span>{pathString}
      </div>
      {currentPath.length > 0 && (
        <button
          className="mb-4 px-4 py-2 bg-gray-500 text-white rounded hover:bg-gray-600"
          onClick={handleBack}
        >
          Back
        </button>
      )}
      <div className="mb-4">
        <label className="block mb-2">
          Derivation Path:
          <input
            type="text"
            className="ml-2 p-1 border rounded"
            value={derivationPath}
            onChange={(e) => setDerivationPath(e.target.value)}
          />
        </label>
      </div>
      <div className="mb-4">
        <h2 className="text-xl font-semibold mb-2">Child Seed Phrases</h2>
        <div className="space-y-2">
          {childMnemonics.map((mnemonic, index) => (
            <div key={index} className="flex justify-between items-center">
              <span className="text-sm break-all">Child {index}: {mnemonic}</span>
              <button
                className="px-2 py-1 bg-green-500 text-white rounded hover:bg-green-600"
                onClick={() => handleLoadChild(index)}
              >
                Load
              </button>
            </div>
          ))}
        </div>
      </div>
      {/* Comment out the addresses section
      <div>
        <h2 className="text-xl font-semibold mb-2">Derived Addresses</h2>
        <ul className="list-disc pl-5 space-y-1">
          {addresses.map((address, index) => (
            <li key={index} className="text-sm">{address}</li>
          ))}
        </ul>
      </div>
      */}
    </div>
  );
};

export default App;