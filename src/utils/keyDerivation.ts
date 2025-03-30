import * as bip39 from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32 } from 'bech32';
import { sha256 } from 'js-sha256';
import { wordlist } from '@scure/bip39/wordlists/english';

export interface NostrKeys {
  nsec: string;
  npub: string;
}

export interface BitcoinKeys {
  address: string;
  privateKeyWIF: string;
}

export interface DerivedKeys {
  index: number;
  nsec: string;
  npub: string;
  bitcoinAddress: string;
  bitcoinPrivateKey: string;
}

const arrayBufferToUint8Array = (buffer: ArrayBuffer): Uint8Array => {
  return new Uint8Array(buffer);
};

const privateKeyToWIF = (privateKey: Uint8Array): string => {
  const extendedKey = new Uint8Array(34);
  extendedKey[0] = 0x80;
  extendedKey.set(privateKey, 1);
  extendedKey[33] = 0x01;

  const firstSha = arrayBufferToUint8Array(sha256.arrayBuffer(extendedKey));
  const secondSha = arrayBufferToUint8Array(sha256.arrayBuffer(firstSha));

  const finalKey = new Uint8Array(38);
  finalKey.set(extendedKey);
  finalKey.set(secondSha.slice(0, 4), 34);

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

  for (let i = 0; i < finalKey.length && finalKey[i] === 0; i++) {
    wif = '1' + wif;
  }

  return wif;
};

export const deriveNostrKeys = (hdKey: HDKey): NostrKeys => {
  if (!hdKey.privateKey || !hdKey.publicKey) {
    throw new Error('Keys not available in the HDKey');
  }

  const privateKeyWords = bech32.toWords(hdKey.privateKey);
  const publicKeyWords = bech32.toWords(hdKey.publicKey);

  return {
    nsec: bech32.encode('nsec', privateKeyWords),
    npub: bech32.encode('npub', publicKeyWords),
  };
};

export const deriveBitcoinKeys = (hdKey: HDKey, path: string): BitcoinKeys => {
  const derivedKey = hdKey.derive(path);
  if (!derivedKey.publicKey || !derivedKey.privateKey) {
    throw new Error('Keys not available');
  }

  const sha256HashArray = arrayBufferToUint8Array(sha256.arrayBuffer(derivedKey.publicKey));
  const ripemd160Hash = sha256HashArray.slice(0, 20);

  const witnessProgram = new Uint8Array(ripemd160Hash.length + 1);
  witnessProgram[0] = 0x00;
  witnessProgram.set(ripemd160Hash, 1);

  return {
    address: bech32.encode('bc', bech32.toWords(witnessProgram)),
    privateKeyWIF: privateKeyToWIF(derivedKey.privateKey),
  };
};

export const deriveCurrentMnemonic = (rootMnemonic: string, path: number[]): string => {
  const seed = bip39.mnemonicToSeedSync(rootMnemonic);
  const masterKey = HDKey.fromMasterSeed(seed);
  
  if (path.length === 0) {
    const childSeed = masterKey.privateKey;
    return bip39.entropyToMnemonic(childSeed!.slice(0, 16), wordlist);
  }

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

export type PathType = 'bitcoin' | 'nostr' | 'unknown';

export const getPathType = (path: string): PathType => {
  // Bitcoin paths
  if (path.startsWith("m/44'/0'/") || // Legacy
      path.startsWith("m/49'/0'/") || // Nested SegWit
      path.startsWith("m/84'/0'/") || // Native SegWit
      path.startsWith("m/86'/0'/")) { // Taproot
    return 'bitcoin';
  }
  
  // Nostr paths
  if (path.startsWith("m/44'/1237'/")) {
    return 'nostr';
  }

  return 'unknown';
}; 