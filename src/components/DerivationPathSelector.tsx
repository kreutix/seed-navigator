import React, { useState } from 'react';

interface DerivationPathSelectorProps {
  value: string;
  onChange: (path: string) => void;
}

const COMMON_PATHS = {
  bitcoin: [
    { label: 'Native SegWit (P2WPKH)', path: "m/84'/0'/0'/0" },
    { label: 'Nested SegWit (P2SH-P2WPKH)', path: "m/49'/0'/0'/0" },
    { label: 'Legacy (P2PKH)', path: "m/44'/0'/0'/0" },
    { label: 'Taproot (P2TR)', path: "m/86'/0'/0'/0" }
  ],
  nostr: [
    { label: 'Nostr BIP-32', path: "m/44'/1237'/0'/0" },
    { label: 'Nostr BIP-44', path: "m/44'/1237'/0'/0/0" }
  ]
};

export const DerivationPathSelector: React.FC<DerivationPathSelectorProps> = ({ value, onChange }) => {
  const [showSelect, setShowSelect] = useState(true);
  const allPaths = [...COMMON_PATHS.bitcoin, ...COMMON_PATHS.nostr];
  const currentTemplate = allPaths.find(p => p.path === value);

  const handleSelectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const newValue = e.target.value;
    if (newValue !== 'select') {
      onChange(newValue);
      setShowSelect(false);
    }
  };

  return (
    <div className="flex items-center gap-2">
      {showSelect ? (
        <select
          value="select"
          onChange={handleSelectChange}
          className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-gray-300"
        >
          <option value="select" disabled className="bg-gray-900">
            Select template...
          </option>
          <optgroup label="Bitcoin" className="bg-gray-900">
            {COMMON_PATHS.bitcoin.map(({ label, path }) => (
              <option key={path} value={path} className="bg-gray-900">
                {label}
              </option>
            ))}
          </optgroup>
          <optgroup label="Nostr" className="bg-gray-900">
            {COMMON_PATHS.nostr.map(({ label, path }) => (
              <option key={path} value={path} className="bg-gray-900">
                {label}
              </option>
            ))}
          </optgroup>
        </select>
      ) : (
        <div className="flex-1 flex items-center gap-2">
          <input
            type="text"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-gray-300"
          />
        </div>
      )}
      {!showSelect && (
        <button
          onClick={() => setShowSelect(true)}
          className="px-2 py-1.5 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors duration-200 text-sm"
          title="Back to templates"
        >
          ←
        </button>
      )}
    </div>
  );
}; 