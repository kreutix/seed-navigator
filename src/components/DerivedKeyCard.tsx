import { DerivedKeys } from '../utils/keyDerivation';
import { KeyDisplay } from './KeyDisplay';

interface DerivedKeyCardProps {
  keys: DerivedKeys;
  type: 'bitcoin' | 'nostr';
}

const BitcoinKeys: React.FC<{ address: string; privateKey: string }> = ({ address, privateKey }) => (
  <div className="space-y-3">
    <KeyDisplay label="Bitcoin Address" value={address} />
    <KeyDisplay label="Bitcoin Private Key (WIF)" value={privateKey} />
  </div>
);

const NostrKeys: React.FC<{ nsec: string; npub: string }> = ({ nsec, npub }) => (
  <div className="space-y-3">
    <KeyDisplay label="Nostr Private Key (nsec)" value={nsec} />
    <KeyDisplay label="Nostr Public Key (npub)" value={npub} />
  </div>
);

export const DerivedKeyCard: React.FC<DerivedKeyCardProps> = ({ keys, type }) => (
  <div className="bg-gray-900 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors duration-200">
    <div className="flex items-center justify-between mb-3">
      <span className="text-sm font-semibold text-gray-400">Index {keys.index}</span>
      <span className="px-2 py-1 bg-gray-800 rounded-full text-xs text-gray-400 border border-gray-700">
        #{keys.index}
      </span>
    </div>
    
    {type === 'bitcoin' ? (
      <BitcoinKeys address={keys.bitcoinAddress} privateKey={keys.bitcoinPrivateKey} />
    ) : (
      <NostrKeys nsec={keys.nsec} npub={keys.npub} />
    )}
  </div>
); 