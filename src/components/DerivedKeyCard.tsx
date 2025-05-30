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
  index: number;
  toggleDetails?: () => void;
  showDetailsButton?: boolean;
  showDetails?: boolean;
}

const KeyField: React.FC<KeyFieldProps> = ({ 
  label, 
  value, 
  index,
  toggleDetails, 
  showDetailsButton = false,
  showDetails
}) => (
  <div className="flex items-center gap-2 p-0">
    <span className="text-xs text-gray-400 whitespace-nowrap">
      {label} #{index}
    </span>
    <div className="flex-1 font-mono text-sm text-gray-300 break-all bg-gray-800 p-1.5 rounded border border-gray-700">
      {value}
    </div>
    <div className="flex items-center gap-1.5">
      <CopyButton text={value} />
      {showDetailsButton && (
        <button 
          onClick={toggleDetails}
          className="p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded border border-gray-700 text-xs font-medium transition-colors duration-200"
        >
          {showDetails ? "Hide" : "Details"}
        </button>
      )}
    </div>
  </div>
);

const BitcoinKeys: React.FC<{ address: string; privateKey: string; publicKey: string; publicKeyHash: string; publicKeyHash160: string; witnessProgram: string; checksum: string; index: number }> = ({ 
  address, 
  privateKey, 
  publicKey,
  publicKeyHash,
  publicKeyHash160,
  witnessProgram,
  checksum,
  index
}) => {
  const [showDetails, setShowDetails] = useState(false);
  
  const toggleDetails = () => setShowDetails(!showDetails);

  return (
    <div className="space-y-1">
      <KeyField 
        label="Bitcoin Address"
        value={address} 
        index={index}
        toggleDetails={toggleDetails}
        showDetailsButton={true}
        showDetails={showDetails}
      />
      
      {showDetails && (
        <div className="space-y-1 border-t border-gray-700 pt-1">
          <KeyField label="Bitcoin Private Key (WIF)" value={privateKey} index={index} />
          <KeyField label="Public Key (hex)" value={publicKey} index={index} />
          <KeyField label="Public Key Hash (SHA256)" value={publicKeyHash} index={index} />
          <KeyField label="Public Key Hash (RIPEMD160)" value={publicKeyHash160} index={index} />
          {witnessProgram && <KeyField label="Witness Program (P2WPKH)" value={witnessProgram} index={index} />}
          {checksum && <KeyField label="Checksum (Legacy)" value={checksum} index={index} />}
        </div>
      )}
    </div>
  );
};

const NostrKeys: React.FC<{ nsec: string; npub: string; index: number }> = ({ nsec, npub, index }) => (
  <div className="space-y-1">
    <KeyField label="Nostr Private Key (nsec)" value={nsec} index={index} />
    <KeyField label="Nostr Public Key (npub)" value={npub} index={index} />
  </div>
);

export const DerivedKeyCard: React.FC<DerivedKeyCardProps> = ({ keys, type }) => (
  <div className="bg-gray-900 rounded-lg border border-gray-700 p-2 hover:border-gray-600 transition-colors duration-200">
    {type === 'bitcoin' ? (
      <BitcoinKeys 
        address={keys.bitcoinAddress} 
        privateKey={keys.bitcoinPrivateKey} 
        publicKey={keys.bitcoinPublicKey} 
        publicKeyHash={keys.bitcoinPublicKeyHash} 
        publicKeyHash160={keys.bitcoinPublicKeyHash160} 
        witnessProgram={keys.bitcoinWitnessProgram} 
        checksum={keys.bitcoinChecksum}
        index={keys.index} 
      />
    ) : (
      <NostrKeys nsec={keys.nsec} npub={keys.npub} index={keys.index} />
    )}
  </div>
);
