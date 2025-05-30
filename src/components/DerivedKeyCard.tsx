import { useState } from 'react';
import { DerivedKeys } from '../utils/keyDerivation';
import { CopyButton } from './CopyButton';

interface DerivedKeyCardProps {
  keys: DerivedKeys;
  type: 'bitcoin' | 'nostr';
}

interface KeyFieldProps {
  label: string;
  value: string;
  toggleDetails?: () => void;
  showDetailsButton?: boolean;
  showDetails?: boolean;
}

const KeyField: React.FC<KeyFieldProps> = ({ 
  label, 
  value, 
  toggleDetails, 
  showDetailsButton = false,
  showDetails
}) => (
  <div className="space-y-1">
    <div className="text-xs font-medium text-gray-400">{label}</div>
    <div className="flex items-center gap-2">
      <div className="flex-1 font-mono text-sm text-gray-300 break-all bg-gray-800 p-2 rounded border border-gray-700">
        {value}
      </div>
      <CopyButton text={value} />
      {showDetailsButton && (
        <button 
          onClick={toggleDetails}
          className="px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded border border-gray-700 text-xs font-medium transition-colors duration-200"
        >
          {showDetails ? "Hide" : "Details"}
        </button>
      )}
    </div>
  </div>
);

const BitcoinKeys: React.FC<{ address: string; privateKey: string; publicKey: string; publicKeyHash: string; publicKeyHash160: string; witnessProgram: string; checksum: string }> = ({ 
  address, 
  privateKey, 
  publicKey,
  publicKeyHash,
  publicKeyHash160,
  witnessProgram,
  checksum
}) => {
  const [showDetails, setShowDetails] = useState(false);
  
  const toggleDetails = () => setShowDetails(!showDetails);

  return (
    <div className="space-y-3">
      <KeyField 
        label="Bitcoin Address" 
        value={address} 
        toggleDetails={toggleDetails}
        showDetailsButton={true}
        showDetails={showDetails}
      />
      
      {showDetails && (
        <div className="space-y-3 border-t border-gray-700 pt-3">
          <KeyField label="Bitcoin Private Key (WIF)" value={privateKey} />
          <KeyField label="Public Key (hex)" value={publicKey} />
          <KeyField label="Public Key Hash (SHA256)" value={publicKeyHash} />
          <KeyField label="Public Key Hash (RIPEMD160)" value={publicKeyHash160} />
          {witnessProgram && <KeyField label="Witness Program (P2WPKH)" value={witnessProgram} />}
          {checksum && <KeyField label="Checksum (Legacy)" value={checksum} />}
        </div>
      )}
    </div>
  );
};

const NostrKeys: React.FC<{ nsec: string; npub: string }> = ({ nsec, npub }) => (
  <div className="space-y-3">
    <KeyField label="Nostr Private Key (nsec)" value={nsec} />
    <KeyField label="Nostr Public Key (npub)" value={npub} />
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
      <BitcoinKeys address={keys.bitcoinAddress} privateKey={keys.bitcoinPrivateKey} publicKey={keys.bitcoinPublicKey} publicKeyHash={keys.bitcoinPublicKeyHash} publicKeyHash160={keys.bitcoinPublicKeyHash160} witnessProgram={keys.bitcoinWitnessProgram} checksum={keys.bitcoinChecksum} />
    ) : (
      <NostrKeys nsec={keys.nsec} npub={keys.npub} />
    )}
  </div>
);
