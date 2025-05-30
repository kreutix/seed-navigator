import React, { useState, useRef, useEffect } from 'react';

interface DerivationPathSelectorProps {
  value: string;
  onChange: (path: string) => void;
}

interface PathTemplate {
  label: string;
  path: string;
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
  const [isOpen, setIsOpen] = useState(false);
  const [inputValue, setInputValue] = useState(value);
  const [highlightedIndex, setHighlightedIndex] = useState(-1);
  const inputRef = useRef<HTMLInputElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  // Update input value when prop value changes
  useEffect(() => {
    setInputValue(value);
  }, [value]);

  // Handle outside clicks to close dropdown
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current && 
        !dropdownRef.current.contains(event.target as Node) &&
        inputRef.current && 
        !inputRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    };
    
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  // Get all suggestions - always return all paths
  const getAllSuggestions = () => {
    return {
      bitcoin: COMMON_PATHS.bitcoin,
      nostr: COMMON_PATHS.nostr
    };
  };

  // Highlight text that matches the input
  const highlightMatch = (text: string) => {
    if (!inputValue) return text;
    
    const lowerText = text.toLowerCase();
    const lowerInput = inputValue.toLowerCase();
    
    if (!lowerText.includes(lowerInput)) return text;
    
    const startIndex = lowerText.indexOf(lowerInput);
    const endIndex = startIndex + lowerInput.length;
    
    return (
      <>
        {text.substring(0, startIndex)}
        <span className="font-bold text-white">{text.substring(startIndex, endIndex)}</span>
        {text.substring(endIndex)}
      </>
    );
  };

  // Check if an item matches the input for styling
  const isMatch = (item: PathTemplate) => {
    if (!inputValue) return false;
    
    const lowerInput = inputValue.toLowerCase();
    return (
      item.label.toLowerCase().includes(lowerInput) || 
      item.path.toLowerCase().includes(lowerInput)
    );
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const newValue = e.target.value;
    setInputValue(newValue);
    onChange(newValue);
    setIsOpen(true);
    setHighlightedIndex(-1);
  };

  const handleInputFocus = () => {
    setIsOpen(true);
  };

  const handleSuggestionClick = (suggestion: PathTemplate) => {
    setInputValue(suggestion.path);
    onChange(suggestion.path);
    setIsOpen(false);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    const allSuggestions = getAllSuggestions();
    const flatSuggestions = [...allSuggestions.bitcoin, ...allSuggestions.nostr];
    
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setIsOpen(true);
        setHighlightedIndex(prev => 
          prev < flatSuggestions.length - 1 ? prev + 1 : 0
        );
        break;
      case 'ArrowUp':
        e.preventDefault();
        setIsOpen(true);
        setHighlightedIndex(prev => 
          prev > 0 ? prev - 1 : flatSuggestions.length - 1
        );
        break;
      case 'Enter':
        e.preventDefault();
        if (isOpen && highlightedIndex >= 0 && highlightedIndex < flatSuggestions.length) {
          handleSuggestionClick(flatSuggestions[highlightedIndex]);
        }
        break;
      case 'Escape':
        e.preventDefault();
        setIsOpen(false);
        break;
      case 'Tab':
        setIsOpen(false);
        break;
    }
  };

  const allSuggestions = getAllSuggestions();
  const flatSuggestions = [...allSuggestions.bitcoin, ...allSuggestions.nostr];
  
  return (
    <div className="relative w-full">
      <div className="relative">
        <input
          ref={inputRef}
          type="text"
          value={inputValue}
          onChange={handleInputChange}
          onFocus={handleInputFocus}
          onKeyDown={handleKeyDown}
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 pr-8 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition text-gray-300"
          placeholder="Enter derivation path..."
        />
        <button 
          onClick={() => setIsOpen(!isOpen)}
          className="absolute right-2 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-300"
        >
          <svg 
            xmlns="http://www.w3.org/2000/svg" 
            className={`h-4 w-4 transition-transform duration-200 ${isOpen ? 'rotate-180' : ''}`} 
            fill="none" 
            viewBox="0 0 24 24" 
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>

      {isOpen && (
        <div 
          ref={dropdownRef}
          className="absolute z-10 mt-1 w-full bg-gray-800 border border-gray-700 rounded-lg shadow-lg max-h-60 overflow-auto"
        >
          {flatSuggestions.length === 0 ? (
            <div className="px-3 py-2 text-sm text-gray-400">No matches found</div>
          ) : (
            <>
              {allSuggestions.bitcoin.length > 0 && (
                <div>
                  <div className="px-3 py-1 text-xs font-medium text-gray-400 bg-gray-850">Bitcoin</div>
                  {allSuggestions.bitcoin.map((suggestion, index) => {
                    const flatIndex = index;
                    const isHighlighted = flatIndex === highlightedIndex;
                    const matchesInput = isMatch(suggestion);
                    
                    return (
                      <div
                        key={suggestion.path}
                        onClick={() => handleSuggestionClick(suggestion)}
                        className={`px-3 py-2 cursor-pointer ${
                          isHighlighted ? 'bg-gray-700' : matchesInput ? 'bg-gray-750' : 'hover:bg-gray-700'
                        }`}
                      >
                        <div className="font-medium text-sm text-gray-200">
                          {highlightMatch(suggestion.label)}
                        </div>
                        <div className="text-xs font-mono text-gray-400">
                          {highlightMatch(suggestion.path)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
              
              {allSuggestions.nostr.length > 0 && (
                <div>
                  <div className="px-3 py-1 text-xs font-medium text-gray-400 bg-gray-850">Nostr</div>
                  {allSuggestions.nostr.map((suggestion, index) => {
                    const flatIndex = allSuggestions.bitcoin.length + index;
                    const isHighlighted = flatIndex === highlightedIndex;
                    const matchesInput = isMatch(suggestion);
                    
                    return (
                      <div
                        key={suggestion.path}
                        onClick={() => handleSuggestionClick(suggestion)}
                        className={`px-3 py-2 cursor-pointer ${
                          isHighlighted ? 'bg-gray-700' : matchesInput ? 'bg-gray-750' : 'hover:bg-gray-700'
                        }`}
                      >
                        <div className="font-medium text-sm text-gray-200">
                          {highlightMatch(suggestion.label)}
                        </div>
                        <div className="text-xs font-mono text-gray-400">
                          {highlightMatch(suggestion.path)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};
