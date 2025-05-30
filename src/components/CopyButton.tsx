import React from 'react';
import { Tooltip } from 'react-tooltip';
import 'react-tooltip/dist/react-tooltip.css';

import { useClipboard } from '../hooks/useClipboard';
import { CopyButtonProps } from '../types';

/**
 * CopyButton component for copying text to clipboard
 * 
 * Features:
 * - Secure clipboard operations with proper error handling
 * - Visual feedback when copy succeeds or fails
 * - Tooltip with status information
 * - Accessibility support
 * 
 * @param text - Text to copy to clipboard
 * @param className - Optional additional CSS classes
 */
export const CopyButton: React.FC<CopyButtonProps> = ({ 
  text, 
  className = '' 
}) => {
  // Use the clipboard hook with 2 second success duration
  const { copied, error, copyToClipboard } = useClipboard({
    successDuration: 2000,
    onError: (err) => console.error('Failed to copy:', err)
  });

  // Handle copy button click
  const handleCopy = async () => {
    if (!text) return; // Don't attempt to copy empty text
    await copyToClipboard(text);
  };

  // Determine tooltip content based on state
  const tooltipContent = error 
    ? `Failed to copy: ${error.message}` 
    : copied 
      ? 'Copied!' 
      : 'Copy to clipboard';

  return (
    <>
      <button
        onClick={handleCopy}
        className={`p-2 text-gray-400 hover:text-gray-200 transition-colors duration-200 ${
          error ? 'text-red-400 hover:text-red-300' : 
          copied ? 'text-green-400 hover:text-green-300' : ''
        } ${className}`}
        data-tooltip-id="copy-tooltip"
        data-tooltip-content={tooltipContent}
        aria-label={tooltipContent}
        disabled={!text} // Disable button if text is empty
        type="button" // Explicitly set button type
      >
        {copied ? (
          <svg 
            className="w-4 h-4" 
            fill="none" 
            stroke="currentColor" 
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M5 13l4 4L19 7" 
            />
          </svg>
        ) : error ? (
          <svg 
            className="w-4 h-4" 
            fill="none" 
            stroke="currentColor" 
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M6 18L18 6M6 6l12 12" 
            />
          </svg>
        ) : (
          <svg 
            className="w-4 h-4" 
            fill="none" 
            stroke="currentColor" 
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path 
              strokeLinecap="round" 
              strokeLinejoin="round" 
              strokeWidth={2} 
              d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3" 
            />
          </svg>
        )}
      </button>
      <Tooltip 
        id="copy-tooltip" 
        place="top"
        delayShow={300}
        className={error ? 'bg-red-700' : copied ? 'bg-green-700' : ''}
      />
    </>
  );
};
