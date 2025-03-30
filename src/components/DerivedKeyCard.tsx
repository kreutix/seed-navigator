import { DerivedKeys } from '../utils/keyDerivation';
import { KeyDisplay } from './KeyDisplay';

interface DerivedKeyCardProps {
  keys: DerivedKeys;
}

export const DerivedKeyCard: React.FC<DerivedKeyCardProps> = ({ keys }) => (
  <div className="bg-gray-900 rounded-lg border border-gray-700 p-4 hover:border-gray-600 transition-colors duration-200">
    <div className="flex items-center justify-between mb-3">
      <span className="text-sm font-semibold text-gray-400">Index {keys.index}</span>
      <span className="px-2 py-1 bg-gray-800 rounded-full text-xs text-gray-400 border border-gray-700">
        #{keys.index}
      </span>
    </div>
    
    <div className="space-y-3">
      <KeyDisplay label="Nostr Private Key (nsec)" value={keys.nsec} />
      <KeyDisplay label="Nostr Public Key (npub)" value={keys.npub} />
      <KeyDisplay label="Bitcoin Address" value={keys.bitcoinAddress} />
      <KeyDisplay label="Bitcoin Private Key (WIF)" value={keys.bitcoinPrivateKey} />
    </div>
  </div>
); 