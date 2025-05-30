import { useState, useCallback, useEffect, useRef } from 'react';
import { createError, ErrorType } from '../utils/crypto';

export interface ClipboardState {
  /**
   * Whether the text was successfully copied
   */
  copied: boolean;
  
  /**
   * Error that occurred during the copy operation, if any
   */
  error: Error | null;
  
  /**
   * Function to copy text to the clipboard
   */
  copyToClipboard: (text: string) => Promise<boolean>;
  
  /**
   * Function to reset the copied state
   */
  resetCopiedState: () => void;
}

export interface ClipboardOptions {
  /**
   * Duration in milliseconds to show the copied state
   * @default 2000
   */
  successDuration?: number;
  
  /**
   * Callback to run when copy is successful
   */
  onSuccess?: () => void;
  
  /**
   * Callback to run when copy fails
   */
  onError?: (error: Error) => void;
  
  /**
   * Whether to use document.execCommand as a fallback
   * @default true
   */
  useFallback?: boolean;
}

/**
 * Custom hook for secure clipboard operations
 * 
 * Features:
 * - Safe clipboard write with error handling
 * - Success state management with timeout
 * - Fallback methods for unsupported browsers
 * - Security considerations for sensitive data
 * 
 * @param options Configuration options
 * @returns ClipboardState object with state and functions
 */
export function useClipboard(options: ClipboardOptions = {}): ClipboardState {
  // Default options
  const {
    successDuration = 2000,
    onSuccess,
    onError,
    useFallback = true
  } = options;
  
  // State
  const [copied, setCopied] = useState<boolean>(false);
  const [error, setError] = useState<Error | null>(null);
  
  // Ref for timeout to allow proper cleanup
  const timeoutRef = useRef<number | null>(null);
  
  /**
   * Reset the copied state and error
   */
  const resetCopiedState = useCallback(() => {
    setCopied(false);
    setError(null);
    
    // Clear any existing timeout
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
  }, []);
  
  /**
   * Copy text to clipboard using the Clipboard API
   * @param text Text to copy
   * @returns Promise that resolves to true if successful, false otherwise
   */
  const copyUsingClipboardAPI = useCallback(async (text: string): Promise<boolean> => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      throw createError(
        `Clipboard API failed: ${err instanceof Error ? err.message : String(err)}`,
        ErrorType.CLIPBOARD_ERROR,
        err
      );
    }
  }, []);
  
  /**
   * Copy text to clipboard using the execCommand fallback
   * @param text Text to copy
   * @returns Promise that resolves to true if successful, false otherwise
   */
  const copyUsingExecCommand = useCallback((text: string): Promise<boolean> => {
    return new Promise((resolve, reject) => {
      try {
        // Create a temporary textarea element
        const textarea = document.createElement('textarea');
        
        // Set its value to the text to copy
        textarea.value = text;
        
        // Make it invisible but part of the document
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        textarea.style.top = '0';
        textarea.setAttribute('readonly', '');
        
        // Add it to the document
        document.body.appendChild(textarea);
        
        // Select the text
        textarea.select();
        
        // Try to copy
        const successful = document.execCommand('copy');
        
        // Remove the temporary element
        document.body.removeChild(textarea);
        
        // Check if it worked
        if (successful) {
          resolve(true);
        } else {
          reject(createError(
            'execCommand copy operation failed',
            ErrorType.CLIPBOARD_ERROR
          ));
        }
      } catch (err) {
        reject(createError(
          `execCommand fallback failed: ${err instanceof Error ? err.message : String(err)}`,
          ErrorType.CLIPBOARD_ERROR,
          err
        ));
      }
    });
  }, []);
  
  /**
   * Copy text to clipboard with fallback support
   * @param text Text to copy
   * @returns Promise that resolves to true if successful, false otherwise
   */
  const copyToClipboard = useCallback(async (text: string): Promise<boolean> => {
    // Reset any previous state
    resetCopiedState();
    
    try {
      // Check if text is empty
      if (!text) {
        throw createError(
          'Cannot copy empty text',
          ErrorType.VALIDATION_ERROR
        );
      }
      
      let success = false;
      
      // Try using the Clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        success = await copyUsingClipboardAPI(text);
      } else if (useFallback) {
        // Fall back to execCommand if the Clipboard API is not available
        success = await copyUsingExecCommand(text);
      } else {
        throw createError(
          'Clipboard API not available and fallback is disabled',
          ErrorType.CLIPBOARD_ERROR
        );
      }
      
      // Update state on success
      if (success) {
        setCopied(true);
        
        // Call success callback if provided
        if (onSuccess) {
          onSuccess();
        }
        
        // Set timeout to reset the copied state
        timeoutRef.current = window.setTimeout(() => {
          setCopied(false);
          timeoutRef.current = null;
        }, successDuration);
      }
      
      return success;
    } catch (err) {
      // Handle errors
      const error = err instanceof Error ? err : new Error(String(err));
      
      setError(error);
      
      // Call error callback if provided
      if (onError) {
        onError(error);
      }
      
      console.error('Clipboard copy failed:', error);
      
      return false;
    }
  }, [
    copyUsingClipboardAPI,
    copyUsingExecCommand,
    onError,
    onSuccess,
    resetCopiedState,
    successDuration,
    useFallback
  ]);
  
  // Clean up any timeouts when the component unmounts
  useEffect(() => {
    return () => {
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current);
      }
    };
  }, []);
  
  return {
    copied,
    error,
    copyToClipboard,
    resetCopiedState
  };
}

/**
 * Checks if the Clipboard API is available in the current browser
 * @returns True if the Clipboard API is available
 */
export function isClipboardApiSupported(): boolean {
  return !!(
    typeof navigator !== 'undefined' &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === 'function'
  );
}

/**
 * Checks if the execCommand fallback is available in the current browser
 * @returns True if the execCommand fallback is available
 */
export function isExecCommandSupported(): boolean {
  return !!(
    typeof document !== 'undefined' &&
    typeof document.execCommand === 'function'
  );
}

/**
 * Checks if any clipboard method is available
 * @returns True if any clipboard method is available
 */
export function isClipboardSupported(): boolean {
  return isClipboardApiSupported() || isExecCommandSupported();
}
