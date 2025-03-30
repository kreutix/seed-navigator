import React, { useState, useMemo } from 'react';
import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { wordlist } from '@scure/bip39/wordlists/english';
import { deriveCurrentMnemonic, deriveNostrKeys, deriveBitcoinKeys } from './utils/keyDerivation';
import { DerivedKeyCard } from './components/DerivedKeyCard';

const App: React.FC = () => {
  const [rootSeedPhrase, setRootSeedPhrase] = useState('');
  const [currentPath, setCurrentPath] = useState<number[]>([]);
  const [derivationPath, setDerivationPath] = useState("m/84'/0'/0'/0");

  const currentMnemonic = useMemo(() => {
    if (!rootSeedPhrase) return '';
    try {
      return deriveCurrentMnemonic(rootSeedPhrase, currentPath);
    } catch (error) {
      console.error('Error deriving mnemonic:', error);
      return '';
    }
  }, [rootSeedPhrase, currentPath]);

  const childMnemonics = useMemo(() => {
    if (!currentMnemonic) return [];
    try {
      return Array.from({ length: 10 }, (_, i) => {
        return deriveCurrentMnemonic(currentMnemonic, [...currentPath, i]);
      });
    } catch (error) {
      console.error('Error deriving child mnemonics:', error);
      return [];
    }
  }, [currentMnemonic, currentPath]);

  const derivedKeys = useMemo(() => {
    if (!currentMnemonic) return [];
    try {
      const seed = bip39.mnemonicToSeedSync(currentMnemonic);
      const masterKey = HDKey.fromMasterSeed(seed);
      
      return Array.from({ length: 10 }, (_, i) => {
        const path = `${derivationPath}/${i}`;
        const derivedKey = masterKey.derive(path);
        const nostrKeys = deriveNostrKeys(derivedKey);
        const bitcoinKeys = deriveBitcoinKeys(masterKey, path);
        return {
          index: i,
          nsec: nostrKeys.nsec,
          npub: nostrKeys.npub,
          bitcoinAddress: bitcoinKeys.address,
          bitcoinPrivateKey: bitcoinKeys.privateKeyWIF
        };
      });
    } catch (error) {
      console.error('Error deriving keys:', error);
      return [];
    }
  }, [currentMnemonic, derivationPath]);

  const handleSetRootSeed = () => {
    if (!rootSeedPhrase.trim()) return;
    try {
      if (!bip39.validateMnemonic(rootSeedPhrase, wordlist)) {
        alert('Invalid mnemonic phrase');
        return;
      }
      setCurrentPath([]);
    } catch (error) {
      console.error('Error setting root seed:', error);
      alert('Invalid mnemonic phrase');
    }
  };

  if (!rootSeedPhrase) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white p-6">
        <div className="max-w-2xl mx-auto">
          <h1 className="text-4xl font-bold mb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Seed Navigator
          </h1>
          <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700">
            <h2 className="text-xl font-semibold mb-4">Enter BIP39 Seed Phrase</h2>
            <textarea
              className="w-full p-4 bg-gray-900 border border-gray-700 rounded-lg mb-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
              rows={3}
              placeholder="Enter your BIP39 seed phrase here..."
              value={rootSeedPhrase}
              onChange={(e) => setRootSeedPhrase(e.target.value.trim())}
            />
            <button
              className="w-full py-3 px-6 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 transform hover:scale-[1.02] transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-gray-800"
              onClick={handleSetRootSeed}
            >
              Set Root Seed
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-4xl font-bold mb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
          Seed Navigator
        </h1>

        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700 mb-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-4">
              <span className="text-gray-400">Current Path:</span>
              <span className="font-mono bg-gray-900 px-3 py-1 rounded-lg border border-gray-700">
                root/{currentPath.join('/')}{currentPath.length > 0 ? '/' : ''}
              </span>
            </div>
            {currentPath.length > 0 && (
              <button
                className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors duration-200"
                onClick={() => setCurrentPath(currentPath.slice(0, -1))}
              >
                ← Back
              </button>
            )}
          </div>
          
          <div className="flex items-center space-x-4">
            <span className="text-gray-400">Derivation Path:</span>
            <input
              type="text"
              className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
              value={derivationPath}
              onChange={(e) => setDerivationPath(e.target.value)}
            />
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Child Seed Phrases
          </h2>
          <div className="space-y-3">
            {childMnemonics.map((mnemonic, index) => (
              <div key={index} 
                className="flex justify-between items-center p-4 bg-gray-900 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors duration-200">
                <span className="font-mono text-sm text-gray-300 break-all pr-4">
                  Child {index}: {mnemonic}
                </span>
                <button
                  className="px-4 py-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-medium hover:from-blue-600 hover:to-purple-700 transform hover:scale-[1.02] transition-all duration-200"
                  onClick={() => setCurrentPath([...currentPath, index])}
                >
                  Load
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700">
          <h2 className="text-xl font-semibold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Derived Keys
          </h2>
          <div className="grid gap-4">
            {derivedKeys.map((keys) => (
              <DerivedKeyCard key={keys.index} keys={keys} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;