import '@testing-library/jest-dom';
import { afterEach, beforeAll, afterAll, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

// Mock crypto.getRandomValues for deterministic testing
const originalCrypto = global.crypto;

beforeAll(() => {
  // Create a deterministic implementation of getRandomValues
  // This ensures tests are reproducible
  const mockGetRandomValues = vi.fn((array: Uint8Array) => {
    // Fill with predictable values based on array length
    for (let i = 0; i < array.length; i++) {
      array[i] = i % 256;
    }
    return array;
  });

  // Replace the global crypto object
  Object.defineProperty(global, 'crypto', {
    value: {
      ...originalCrypto,
      getRandomValues: mockGetRandomValues,
    },
    writable: true,
  });

  // Silence React error boundary warnings in tests
  const originalConsoleError = console.error;
  console.error = (...args: any[]) => {
    if (
      typeof args[0] === 'string' &&
      args[0].includes('Error boundaries should implement getDerivedStateFromError()')
    ) {
      return;
    }
    originalConsoleError(...args);
  };
});

// Clean up after each test
afterEach(() => {
  cleanup();
});

// Restore original implementations after all tests
afterAll(() => {
  Object.defineProperty(global, 'crypto', {
    value: originalCrypto,
    writable: true,
  });
});

// Handle unhandled promise rejections
if (typeof process !== 'undefined') {
  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled Promise rejection:', reason);
  });
}

// Add custom matchers if needed
expect.extend({
  // Example custom matcher for future use
  toBeValidMnemonic(received: string) {
    const words = received.trim().split(/\s+/);
    const valid = words.length === 12 || words.length === 15 || 
                  words.length === 18 || words.length === 21 || 
                  words.length === 24;
    
    return {
      pass: valid,
      message: () => `expected ${received} ${valid ? 'not ' : ''}to be a valid mnemonic phrase`,
    };
  },
});
