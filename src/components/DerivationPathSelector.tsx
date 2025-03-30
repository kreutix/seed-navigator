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
  return (
    <div className="flex items-center space-x-4">
      <span className="text-gray-400">Derivation Path:</span>
      <div className="flex-1">
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-gray-300"
        >
          <optgroup label="Bitcoin" className="bg-gray-900">
            {COMMON_PATHS.bitcoin.map(({ label, path }) => (
              <option key={path} value={path} className="bg-gray-900">
                {label} ({path})
              </option>
            ))}
          </optgroup>
          <optgroup label="Nostr" className="bg-gray-900">
            {COMMON_PATHS.nostr.map(({ label, path }) => (
              <option key={path} value={path} className="bg-gray-900">
                {label} ({path})
              </option>
            ))}
          </optgroup>
          <optgroup label="Custom" className="bg-gray-900">
            <option value={value} className="bg-gray-900">
              Custom: {value}
            </option>
          </optgroup>
        </select>
      </div>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-gray-300"
        placeholder="Custom derivation path..."
      />
    </div>
  );
}; 