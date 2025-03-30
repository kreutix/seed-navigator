interface KeyDisplayProps {
  label: string;
  value: string;
}

export const KeyDisplay: React.FC<KeyDisplayProps> = ({ label, value }) => (
  <div className="space-y-1">
    <div className="text-xs font-medium text-gray-400">{label}</div>
    <div className="font-mono text-sm text-gray-300 break-all bg-gray-800 p-2 rounded border border-gray-700">
      {value}
    </div>
  </div>
); 