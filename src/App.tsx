import React, { useState, useMemo } from 'react';
import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { wordlist } from '@scure/bip39/wordlists/english';
import { deriveCurrentMnemonic, deriveNostrKeys, deriveBitcoinKeys, getPathType } from './utils/keyDerivation';
import { DerivedKeyCard } from './components/DerivedKeyCard';
import { DerivationPathSelector } from './components/DerivationPathSelector';
import { CopyButton } from './components/CopyButton';

// Helper function to truncate mnemonic to first 4 words
const truncateMnemonic = (mnemonic: string): string => {
  if (!mnemonic) return '';
  const words = mnemonic.split(' ');
  if (words.length <= 6) return mnemonic;
  return words.slice(0, 6).join(' ') + ' ...';
};

const App: React.FC = () => {
  const [rootSeedPhrase, setRootSeedPhrase] = useState('');
  const [currentPath, setCurrentPath] = useState<number[]>([]);
  const [derivationPath, setDerivationPath] = useState("m/84'/0'/0'/0"); // Native SegWit path

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
    try {
      if (currentMnemonic) {
        // Normal case - derive keys from the current mnemonic
        const seed = bip39.mnemonicToSeedSync(currentMnemonic);
        const masterKey = HDKey.fromMasterSeed(seed);
        
        return Array.from({ length: 10 }, (_, i) => {
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
    } catch (error) {
      console.error('Error deriving keys:', error);
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

  const pathType = getPathType(derivationPath);

  const handleSetRootSeed = () => {
    if (!rootSeedPhrase.trim()) return;
    try {
      const words = rootSeedPhrase.trim().split(/\s+/);
      if (words.length !== 24) {
        alert('Please enter a valid 24-word seed phrase');
        return;
      }
      if (!bip39.validateMnemonic(rootSeedPhrase, wordlist)) {
        alert('Invalid BIP39 seed phrase');
        return;
      }
      setCurrentPath([]);
    } catch (error) {
      console.error('Error setting root seed:', error);
      alert('Invalid seed phrase');
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
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Child Seed Phrases
          </h2>
          <div className="space-y-3">
            {childMnemonics.map((mnemonic, index) => (
              <div key={index} 
                className="flex items-center gap-4 p-4 bg-gray-900 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors duration-200">
                <div className="font-mono text-gray-400 min-w-[16px]">
                  {index}:
                </div>
                <div className="flex-1 font-mono text-sm text-gray-300 break-all">
                  {truncateMnemonic(mnemonic)}
                </div>
                <div className="flex items-center gap-2">
                  <CopyButton text={mnemonic} />
                  <button
                    className="p-2 text-gray-400 hover:text-gray-200 transition-colors duration-200"
                    onClick={() => setCurrentPath([...currentPath, index])}
                    title="Load this seed phrase"
                  >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                        d="M13 9l3 3m0 0l-3 3m3-3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
              {pathType === 'nostr' ? 'Nostr Keys' : 'Bitcoin Keys'}
            </h2>
            <div className="flex-1 max-w-xl ml-6">
              <DerivationPathSelector
                value={derivationPath}
                onChange={setDerivationPath}
              />
            </div>
          </div>
          <div className="grid gap-4">
            {derivedKeys.map((keys) => (
              <DerivedKeyCard 
                key={keys.index} 
                keys={keys} 
                type={pathType === 'nostr' ? 'nostr' : 'bitcoin'}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;