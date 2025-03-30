import React, { useState, useMemo } from 'react';
import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32 } from 'bech32';
import { sha256 } from 'js-sha256';
import { wordlist } from '@scure/bip39/wordlists/english';

// Function to derive Nostr keys from HDKey
function deriveNostrKeys(hdKey: HDKey): { nsec: string; npub: string } {
  if (!hdKey.privateKey || !hdKey.publicKey) {
    throw new Error('Keys not available in the HDKey');
  }

  // Derive nsec (private key)
  const privateKeyBytes = hdKey.privateKey;
  const privateKeyWords = bech32.toWords(privateKeyBytes);
  const nsec = bech32.encode('nsec', privateKeyWords);

  // Derive npub (public key)
  const publicKeyBytes = hdKey.publicKey;
  const publicKeyWords = bech32.toWords(publicKeyBytes);
  const npub = bech32.encode('npub', publicKeyWords);

  return { nsec, npub };
}

// Helper function to convert ArrayBuffer to Uint8Array
function arrayBufferToUint8Array(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

// Helper function to convert private key to WIF format
function privateKeyToWIF(privateKey: Uint8Array, compressed: boolean = true): string {
  // Add version byte (0x80 for mainnet) and compression flag if needed
  const extendedKey = new Uint8Array(compressed ? 34 : 33);
  extendedKey[0] = 0x80; // Version byte
  extendedKey.set(privateKey, 1);
  if (compressed) {
    extendedKey[33] = 0x01; // Compression flag
  }

  // Double SHA256
  const firstSha = arrayBufferToUint8Array(sha256.arrayBuffer(extendedKey.slice(0, compressed ? 34 : 33)));
  const secondSha = arrayBufferToUint8Array(sha256.arrayBuffer(firstSha));

  // Add checksum
  const finalKey = new Uint8Array(compressed ? 38 : 37);
  finalKey.set(extendedKey.slice(0, compressed ? 34 : 33));
  finalKey.set(secondSha.slice(0, 4), compressed ? 34 : 33);

  // Base58 encode
  const BASE58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let num = BigInt(0);
  for (let i = 0; i < finalKey.length; i++) {
    num = num * BigInt(256) + BigInt(finalKey[i]);
  }

  let wif = '';
  while (num > BigInt(0)) {
    const mod = num % BigInt(58);
    wif = BASE58_CHARS[Number(mod)] + wif;
    num = num / BigInt(58);
  }

  // Add leading 1's for zero bytes
  for (let i = 0; i < finalKey.length && finalKey[i] === 0; i++) {
    wif = '1' + wif;
  }

  return wif;
}

// Function to derive Bitcoin keys and address from HDKey
function deriveBitcoinKeys(hdKey: HDKey, path: string): { address: string; privateKeyWIF: string } {
  const derivedKey = hdKey.derive(path);
  if (!derivedKey.publicKey || !derivedKey.privateKey) {
    throw new Error('Keys not available');
  }

  // Derive address
  const sha256HashArray = arrayBufferToUint8Array(sha256.arrayBuffer(derivedKey.publicKey));
  const ripemd160Hash = sha256HashArray.slice(0, 20); // Simplified RIPEMD160

  const witnessProgram = new Uint8Array(ripemd160Hash.length + 1);
  witnessProgram[0] = 0x00;
  witnessProgram.set(ripemd160Hash, 1);

  const words = bech32.toWords(witnessProgram);
  const address = bech32.encode('bc', words);

  // Derive WIF private key
  const privateKeyWIF = privateKeyToWIF(derivedKey.privateKey);

  return { address, privateKeyWIF };
}

// Function to derive the current mnemonic based on the root seed and path
const deriveCurrentMnemonic = (rootMnemonic: string, path: number[]): string => {
  const seed = bip39.mnemonicToSeedSync(rootMnemonic);
  const masterKey = HDKey.fromMasterSeed(seed);
  
  // Only derive if path is not empty
  if (path.length === 0) {
    const childSeed = masterKey.privateKey;
    return bip39.entropyToMnemonic(childSeed!.slice(0, 16), wordlist);
  }

  // Convert path numbers to hardened indices
  const derivationPath = path.map(index => `${index}'`).join('/');
  const fullPath = `m/${derivationPath}`;
  
  try {
    const derivedKey = masterKey.derive(fullPath);
    const childSeed = derivedKey.privateKey;
    return bip39.entropyToMnemonic(childSeed!.slice(0, 16), wordlist);
  } catch (error) {
    console.error('Derivation error:', error);
    throw new Error(`Invalid derivation path: ${fullPath}`);
  }
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
        return deriveCurrentMnemonic(currentMnemonic, [...currentPath, i]);
      });
    } catch (error) {
      console.error('Error deriving child mnemonics:', error);
      return [];
    }
  }, [currentMnemonic, currentPath]);

  // Derive Nostr keys and Bitcoin addresses
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
      <div>
        <h2 className="text-xl font-semibold mb-2">Derived Keys</h2>
        <div className="space-y-4">
          {derivedKeys.map(({ index, nsec, npub, bitcoinAddress, bitcoinPrivateKey }) => (
            <div key={index} className="border p-3 rounded">
              <div className="font-semibold text-sm mb-1">Index {index}</div>
              <div className="text-sm break-all mb-1">
                <span className="font-medium">Nostr nsec:</span> {nsec}
              </div>
              <div className="text-sm break-all mb-1">
                <span className="font-medium">Nostr npub:</span> {npub}
              </div>
              <div className="text-sm break-all mb-1">
                <span className="font-medium">Bitcoin Address:</span> {bitcoinAddress}
              </div>
              <div className="text-sm break-all">
                <span className="font-medium">Bitcoin Private Key (WIF):</span> {bitcoinPrivateKey}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default App;