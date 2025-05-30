import React, { useState } from 'react';
import { ErrorBoundary } from 'react-error-boundary';
import { Tooltip } from 'react-tooltip';
import 'react-tooltip/dist/react-tooltip.css';

import { useSeedDerivation } from './hooks/useSeedDerivation';
import { DerivedKeyCard } from './components/DerivedKeyCard';
import { DerivationPathSelector } from './components/DerivationPathSelector';
import { CopyButton } from './components/CopyButton';
import { AppError, ErrorType } from './types';

/**
 * Error Fallback component to display when an error occurs
 */
const ErrorFallback: React.FC<{ error: Error; resetErrorBoundary: () => void }> = ({ 
  error, 
  resetErrorBoundary 
}) => {
  const isAppError = 'type' in error;
  const errorType = isAppError ? (error as AppError).type : ErrorType.UNKNOWN_ERROR;
  
  return (
    <div className="bg-red-900 text-white p-4 rounded-lg mb-4 border border-red-700">
      <h3 className="text-lg font-semibold mb-2">Something went wrong</h3>
      <p className="mb-2">{error.message}</p>
      {errorType !== ErrorType.UNKNOWN_ERROR && (
        <p className="text-sm text-red-300 mb-3">Error type: {errorType}</p>
      )}
      <button
        onClick={resetErrorBoundary}
        className="px-4 py-2 bg-red-700 hover:bg-red-600 rounded-lg transition-colors duration-200"
      >
        Try again
      </button>
    </div>
  );
};

/**
 * SeedInput component for the initial seed phrase input screen
 */
const SeedInput: React.FC<{
  rootSeedPhrase: string;
  updateRootSeedPhrase: (phrase: string) => void;
  setRootSeed: () => void;
  generateRandomSeed: () => void;
  error: AppError | null;
}> = ({
  rootSeedPhrase,
  updateRootSeedPhrase,
  setRootSeed,
  generateRandomSeed,
  error
}) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white p-6">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-4xl font-bold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
          Seed Navigator
        </h1>
        <p className="text-gray-300 mb-8">
          A tool for exploring BIP39 seed phrases, deriving child seeds using BIP85, and generating 
          Bitcoin and Nostr keys based on BIP32 derivation paths. Navigate through your seed hierarchy 
          and explore derived addresses and keys.
        </p>
        
        {error && (
          <div className="bg-red-900 text-white p-4 rounded-lg mb-4 border border-red-700">
            <p className="font-semibold">Error: {error.message}</p>
            {error.type === ErrorType.VALIDATION_ERROR && (
              <p className="text-sm mt-1">Please check your seed phrase format and try again.</p>
            )}
          </div>
        )}
        
        <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700">
          <h2 className="text-xl font-semibold mb-4">Enter BIP39 Seed Phrase</h2>
          <textarea
            className="w-full p-4 bg-gray-900 border border-gray-700 rounded-lg mb-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
            rows={3}
            placeholder="Enter your BIP39 seed phrase here..."
            value={rootSeedPhrase}
            onChange={(e) => updateRootSeedPhrase(e.target.value)}
            aria-label="Seed phrase input"
          />
          <div className="flex gap-4">
            <button
              className="flex-1 py-3 px-6 bg-gradient-to-r from-blue-500 to-purple-600 text-white rounded-lg font-semibold hover:from-blue-600 hover:to-purple-700 transform hover:scale-[1.02] transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2 focus:ring-offset-gray-800"
              onClick={setRootSeed}
            >
              Set Root Seed
            </button>
            <button
              className="flex-1 py-3 px-6 bg-gradient-to-r from-green-500 to-teal-600 text-white rounded-lg font-semibold hover:from-green-600 hover:to-teal-700 transform hover:scale-[1.02] transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-teal-500 focus:ring-offset-2 focus:ring-offset-gray-800"
              onClick={generateRandomSeed}
            >
              Generate Random Seed
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

/**
 * ChildSeedList component to display the list of child seed phrases
 */
const ChildSeedList: React.FC<{
  childMnemonics: string[];
  truncateMnemonic: (mnemonic: string, wordCount?: number) => string;
  navigateToChild: (index: number) => void;
}> = ({
  childMnemonics,
  truncateMnemonic,
  navigateToChild
}) => {
  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700 mb-6">
      <h2 className="text-xl font-semibold mb-4 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
        Child Seed Phrases
      </h2>
      <div className="space-y-2">
        {childMnemonics.map((mnemonic, index) => (
          <div key={index} 
            className="flex items-center gap-2 p-2 bg-gray-900 rounded-lg border border-gray-700 hover:border-gray-600 transition-colors duration-200">
            <span className="px-2 py-1 bg-gray-800 rounded-full text-xs text-gray-400 border border-gray-700">
              #{index}
            </span>
            <div className="flex-1 font-mono text-sm text-gray-300 break-all bg-gray-800 p-1.5 rounded border border-gray-700">
              {truncateMnemonic(mnemonic)}
            </div>
            <div className="flex items-center gap-1.5">
              <CopyButton text={mnemonic} />
              <button
                className="p-1.5 text-gray-400 hover:text-gray-200 transition-colors duration-200 bg-gray-800 rounded border border-gray-700"
                onClick={() => navigateToChild(index)}
                data-tooltip-id="navigate-tooltip"
                data-tooltip-content="Navigate to this seed phrase"
                aria-label={`Navigate to child seed ${index}`}
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} 
                    d="M13 9l3 3m0 0l-3 3m3-3H8m13 0a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

/**
 * NavigationHeader component for the path display and navigation controls
 */
const NavigationHeader: React.FC<{
  currentPath: number[];
  navigateBack: () => void;
  resetSeed: () => void;
}> = ({
  currentPath,
  navigateBack,
  resetSeed
}) => {
  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-4">
          <span className="text-gray-400">Current Path:</span>
          <span className="font-mono bg-gray-900 px-3 py-1 rounded-lg border border-gray-700">
            root/{currentPath.join('/')}{currentPath.length > 0 ? '/' : ''}
          </span>
        </div>
        <div className="flex space-x-3">
          {currentPath.length > 0 && (
            <button
              className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors duration-200"
              onClick={navigateBack}
              aria-label="Navigate back to parent"
            >
              ← Back
            </button>
          )}
          <button
            className="px-4 py-2 bg-gradient-to-r from-red-500 to-orange-600 text-white rounded-lg hover:from-red-600 hover:to-orange-700 transition-colors duration-200"
            onClick={resetSeed}
            data-tooltip-id="new-seed-tooltip"
            data-tooltip-content="Start over with new seed phrase"
            aria-label="Reset to new seed"
          >
            New Seed
          </button>
        </div>
      </div>
    </div>
  );
};

/**
 * DerivedKeysSection component to display the derived keys
 */
const DerivedKeysSection: React.FC<{
  derivedKeys: any[];
  pathType: string;
  derivationPath: string;
  setDerivationPath: (path: string) => void;
}> = ({
  derivedKeys,
  pathType,
  derivationPath,
  setDerivationPath
}) => {
  return (
    <div className="bg-gray-800 rounded-xl p-6 shadow-xl border border-gray-700">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
          {pathType === 'nostr' ? 'Nostr Keys' : 'Bitcoin Keys'}
        </h2>
        <div className="flex-1 max-w-xl ml-6">
          <DerivationPathSelector
            value={derivationPath}
            onChange={setDerivationPath}
          />
        </div>
      </div>
      <div className="grid gap-4">
        {derivedKeys.map((keys) => (
          <DerivedKeyCard 
            key={keys.index} 
            keys={keys} 
            type={pathType === 'nostr' ? 'nostr' : 'bitcoin'}
          />
        ))}
      </div>
    </div>
  );
};

/**
 * Main App component
 */
const App: React.FC = () => {
  const {
    rootSeedPhrase,
    isRootSeedSet,
    currentPath,
    derivationPath,
    childMnemonics,
    derivedKeys,
    pathType,
    error,
    setDerivationPath,
    navigateToChild,
    navigateBack,
    setRootSeed,
    generateRandomSeed,
    resetSeed,
    updateRootSeedPhrase,
    truncateMnemonic
  } = useSeedDerivation();

  const handleErrorReset = () => {
    // Reset any error state if needed
    resetSeed();
  };

  // If root seed is not set, show the seed input screen
  if (!isRootSeedSet) {
    return (
      <ErrorBoundary
        FallbackComponent={ErrorFallback}
        onReset={handleErrorReset}
      >
        <SeedInput
          rootSeedPhrase={rootSeedPhrase}
          updateRootSeedPhrase={updateRootSeedPhrase}
          setRootSeed={setRootSeed}
          generateRandomSeed={generateRandomSeed}
          error={error}
        />
      </ErrorBoundary>
    );
  }

  // Main application screen when root seed is set
  return (
    <ErrorBoundary
      FallbackComponent={ErrorFallback}
      onReset={handleErrorReset}
    >
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 text-white p-6">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-4xl font-bold mb-8 text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-purple-500">
            Seed Navigator
          </h1>

          {error && (
            <div className="bg-red-900 text-white p-4 rounded-lg mb-4 border border-red-700">
              <p className="font-semibold">Error: {error.message}</p>
            </div>
          )}

          <NavigationHeader
            currentPath={currentPath}
            navigateBack={navigateBack}
            resetSeed={resetSeed}
          />

          <ChildSeedList
            childMnemonics={childMnemonics}
            truncateMnemonic={truncateMnemonic}
            navigateToChild={navigateToChild}
          />

          <DerivedKeysSection
            derivedKeys={derivedKeys}
            pathType={pathType}
            derivationPath={derivationPath}
            setDerivationPath={setDerivationPath}
          />
        </div>
        <Tooltip id="navigate-tooltip" />
        <Tooltip id="new-seed-tooltip" />
      </div>
    </ErrorBoundary>
  );
};

export default App;
