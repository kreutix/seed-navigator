import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { CopyButton } from '../CopyButton';
import { CopyButton as RefactoredCopyButton } from '../CopyButton.refactored';

// Mock the clipboard API
const mockWriteText = vi.fn(() => Promise.resolve());
const mockExecCommand = vi.fn(() => true);

// Store original implementations
let originalClipboard: any;
let originalExecCommand: any;

beforeEach(() => {
  // Save original implementations
  originalClipboard = navigator.clipboard;
  originalExecCommand = document.execCommand;
  
  // Mock clipboard API
  Object.defineProperty(navigator, 'clipboard', {
    value: {
      writeText: mockWriteText,
    },
    writable: true,
  });
  
  // Mock execCommand for fallback
  document.execCommand = mockExecCommand;
  
  // Reset mocks before each test
  vi.clearAllMocks();
});

afterEach(() => {
  // Restore original implementations
  Object.defineProperty(navigator, 'clipboard', {
    value: originalClipboard,
    writable: true,
  });
  
  document.execCommand = originalExecCommand;
});

// Helper function to simulate clipboard API not being available
function mockClipboardUnavailable() {
  Object.defineProperty(navigator, 'clipboard', {
    value: undefined,
    writable: true,
  });
}

// Helper function to simulate both clipboard API and execCommand failing
function mockAllClipboardMethodsFailing() {
  mockClipboardUnavailable();
  document.execCommand = vi.fn(() => false);
}

// Test suite for the original CopyButton component
describe('Original CopyButton Component', () => {
  describe('Rendering and Props', () => {
    it('renders correctly with default props', () => {
      render(<CopyButton text="Test text" />);
      
      const button = screen.getByRole('button');
      expect(button).toBeInTheDocument();
      expect(button).toHaveAttribute('data-tooltip-id', 'copy-tooltip');
      expect(button).toHaveAttribute('data-tooltip-content', 'Copy to clipboard');
    });
    
    it('applies custom className when provided', () => {
      render(<CopyButton text="Test text" className="custom-class" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveClass('custom-class');
    });
    
    it('renders copy icon by default', () => {
      render(<CopyButton text="Test text" />);
      
      const svg = screen.getByRole('button').querySelector('svg');
      expect(svg).toBeInTheDocument();
    });
  });
  
  describe('Copy Functionality', () => {
    it('copies text to clipboard when clicked', async () => {
      const textToCopy = 'Test text to copy';
      render(<CopyButton text={textToCopy} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith(textToCopy);
    });
    
    it('handles different text types correctly', async () => {
      // Test with number converted to string
      render(<CopyButton text="12345" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith('12345');
      
      // Clear mocks and test with empty string
      vi.clearAllMocks();
      render(<CopyButton text="" />);
      
      const emptyButton = screen.getByRole('button');
      await userEvent.click(emptyButton);
      
      // Should still try to copy even with empty string
      expect(mockWriteText).toHaveBeenCalledWith('');
    });
    
    it('uses execCommand fallback when clipboard API is not available', async () => {
      mockClipboardUnavailable();
      
      const textToCopy = 'Fallback test';
      render(<CopyButton text={textToCopy} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockExecCommand).toHaveBeenCalledWith('copy');
    });
    
    it('handles clipboard API errors gracefully', async () => {
      // Mock clipboard API to reject
      mockWriteText.mockRejectedValueOnce(new Error('Clipboard error'));
      
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      render(<CopyButton text="Error test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      expect(consoleErrorSpy.mock.calls[0][0]).toContain('Failed to copy');
      
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('Visual States', () => {
    it('shows success state after successful copy', async () => {
      render(<CopyButton text="Success test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      // Check that the success icon is shown
      await waitFor(() => {
        const successPath = screen.getByRole('button').querySelector('path');
        expect(successPath).toHaveAttribute('d', expect.stringContaining('M5 13l4 4L19 7'));
      });
    });
    
    it('reverts to default state after timeout', async () => {
      vi.useFakeTimers();
      
      render(<CopyButton text="Timeout test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      // Fast-forward time
      vi.advanceTimersByTime(2100);
      
      await waitFor(() => {
        const copyPath = screen.getByRole('button').querySelector('path');
        expect(copyPath).toHaveAttribute('d', expect.stringContaining('M8 5H6a2 2 0 00-2 2v12a2'));
      });
      
      vi.useRealTimers();
    });
  });
  
  describe('Accessibility', () => {
    it('has accessible tooltip content', () => {
      render(<CopyButton text="Accessibility test" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveAttribute('data-tooltip-content', 'Copy to clipboard');
    });
    
    it('is keyboard navigable', async () => {
      render(<CopyButton text="Keyboard test" />);
      
      // Focus the button
      const button = screen.getByRole('button');
      button.focus();
      expect(document.activeElement).toBe(button);
      
      // Trigger with Enter key
      await userEvent.keyboard('{Enter}');
      expect(mockWriteText).toHaveBeenCalledWith('Keyboard test');
      
      // Trigger with Space key
      vi.clearAllMocks();
      await userEvent.keyboard(' ');
      expect(mockWriteText).toHaveBeenCalledWith('Keyboard test');
    });
  });
});

// Test suite for the refactored CopyButton component
describe('Refactored CopyButton Component', () => {
  describe('Rendering and Props', () => {
    it('renders correctly with default props', () => {
      render(<RefactoredCopyButton text="Test text" />);
      
      const button = screen.getByRole('button');
      expect(button).toBeInTheDocument();
      expect(button).toHaveAttribute('data-tooltip-id', 'copy-tooltip');
      expect(button).toHaveAttribute('data-tooltip-content', 'Copy to clipboard');
      expect(button).not.toBeDisabled();
    });
    
    it('applies custom className when provided', () => {
      render(<RefactoredCopyButton text="Test text" className="custom-class" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveClass('custom-class');
    });
    
    it('disables button when text is empty', () => {
      render(<RefactoredCopyButton text="" />);
      
      const button = screen.getByRole('button');
      expect(button).toBeDisabled();
    });
    
    it('sets explicit button type for form safety', () => {
      render(<RefactoredCopyButton text="Test text" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveAttribute('type', 'button');
    });
  });
  
  describe('Copy Functionality', () => {
    it('copies text to clipboard when clicked', async () => {
      const textToCopy = 'Test text to copy';
      render(<RefactoredCopyButton text={textToCopy} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith(textToCopy);
    });
    
    it('does not attempt to copy when text is empty', async () => {
      render(<RefactoredCopyButton text="" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).not.toHaveBeenCalled();
    });
    
    it('uses execCommand fallback when clipboard API is not available', async () => {
      mockClipboardUnavailable();
      
      const textToCopy = 'Fallback test';
      render(<RefactoredCopyButton text={textToCopy} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockExecCommand).toHaveBeenCalledWith('copy');
    });
    
    it('handles clipboard API errors gracefully', async () => {
      // Mock clipboard API to reject
      mockWriteText.mockRejectedValueOnce(new Error('Clipboard error'));
      
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      render(<RefactoredCopyButton text="Error test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      // Check that error icon is shown
      await waitFor(() => {
        const errorPath = screen.getByRole('button').querySelector('path');
        expect(errorPath).toHaveAttribute('d', expect.stringContaining('M6 18L18 6M6 6l12 12'));
      });
      
      consoleErrorSpy.mockRestore();
    });
    
    it('handles both clipboard methods failing', async () => {
      mockAllClipboardMethodsFailing();
      
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      render(<RefactoredCopyButton text="All methods fail test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(consoleErrorSpy).toHaveBeenCalled();
      
      // Check that error state is shown in tooltip
      await waitFor(() => {
        expect(button).toHaveAttribute('data-tooltip-content', expect.stringContaining('Failed to copy'));
      });
      
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('Visual States', () => {
    it('shows success state after successful copy', async () => {
      render(<RefactoredCopyButton text="Success test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      // Check that the success icon is shown
      await waitFor(() => {
        const successPath = screen.getByRole('button').querySelector('path');
        expect(successPath).toHaveAttribute('d', expect.stringContaining('M5 13l4 4L19 7'));
      });
      
      // Check that text color changes to green
      expect(button).toHaveClass('text-green-400');
    });
    
    it('shows error state when copy fails', async () => {
      // Mock clipboard API to reject
      mockWriteText.mockRejectedValueOnce(new Error('Clipboard error'));
      
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      render(<RefactoredCopyButton text="Error state test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      // Check that the error icon is shown
      await waitFor(() => {
        const errorPath = screen.getByRole('button').querySelector('path');
        expect(errorPath).toHaveAttribute('d', expect.stringContaining('M6 18L18 6M6 6l12 12'));
      });
      
      // Check that text color changes to red
      expect(button).toHaveClass('text-red-400');
      
      consoleErrorSpy.mockRestore();
    });
    
    it('reverts to default state after timeout', async () => {
      vi.useFakeTimers();
      
      render(<RefactoredCopyButton text="Timeout test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      // Fast-forward time
      vi.advanceTimersByTime(2100);
      
      await waitFor(() => {
        const copyPath = screen.getByRole('button').querySelector('path');
        expect(copyPath).toHaveAttribute('d', expect.stringContaining('M8 5H6a2 2 0 00-2 2v12a2'));
      });
      
      // Check that text color reverts
      expect(button).not.toHaveClass('text-green-400');
      
      vi.useRealTimers();
    });
  });
  
  describe('Tooltip Behavior', () => {
    it('shows "Copy to clipboard" by default', () => {
      render(<RefactoredCopyButton text="Tooltip test" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveAttribute('data-tooltip-content', 'Copy to clipboard');
    });
    
    it('shows "Copied!" after successful copy', async () => {
      render(<RefactoredCopyButton text="Success tooltip test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      await waitFor(() => {
        expect(button).toHaveAttribute('data-tooltip-content', 'Copied!');
      });
    });
    
    it('shows error message when copy fails', async () => {
      // Mock clipboard API to reject with specific error
      mockWriteText.mockRejectedValueOnce(new Error('Permission denied'));
      
      const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      
      render(<RefactoredCopyButton text="Error tooltip test" />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      await waitFor(() => {
        expect(button).toHaveAttribute('data-tooltip-content', expect.stringContaining('Permission denied'));
      });
      
      consoleErrorSpy.mockRestore();
    });
  });
  
  describe('Accessibility', () => {
    it('has accessible aria-label that updates with state', async () => {
      render(<RefactoredCopyButton text="Accessibility test" />);
      
      const button = screen.getByRole('button');
      expect(button).toHaveAttribute('aria-label', 'Copy to clipboard');
      
      await userEvent.click(button);
      
      await waitFor(() => {
        expect(button).toHaveAttribute('aria-label', 'Copied!');
      });
    });
    
    it('marks SVG icons as aria-hidden', () => {
      render(<RefactoredCopyButton text="SVG accessibility test" />);
      
      const svg = screen.getByRole('button').querySelector('svg');
      expect(svg).toHaveAttribute('aria-hidden', 'true');
    });
    
    it('is keyboard navigable', async () => {
      render(<RefactoredCopyButton text="Keyboard test" />);
      
      // Focus the button
      const button = screen.getByRole('button');
      button.focus();
      expect(document.activeElement).toBe(button);
      
      // Trigger with Enter key
      await userEvent.keyboard('{Enter}');
      expect(mockWriteText).toHaveBeenCalledWith('Keyboard test');
      
      // Trigger with Space key
      vi.clearAllMocks();
      await userEvent.keyboard(' ');
      expect(mockWriteText).toHaveBeenCalledWith('Keyboard test');
    });
  });
  
  describe('Edge Cases', () => {
    it('handles very long text correctly', async () => {
      const longText = 'a'.repeat(10000);
      render(<RefactoredCopyButton text={longText} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith(longText);
    });
    
    it('handles special characters correctly', async () => {
      const specialChars = '!@#$%^&*()_+{}|:"<>?~`-=[]\\;\',./';
      render(<RefactoredCopyButton text={specialChars} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith(specialChars);
    });
    
    it('handles emoji correctly', async () => {
      const emojiText = '😀 👍 🚀 🎉';
      render(<RefactoredCopyButton text={emojiText} />);
      
      const button = screen.getByRole('button');
      await userEvent.click(button);
      
      expect(mockWriteText).toHaveBeenCalledWith(emojiText);
    });
    
    it('handles multiple rapid clicks correctly', async () => {
      render(<RefactoredCopyButton text="Rapid clicks test" />);
      
      const button = screen.getByRole('button');
      
      // Click multiple times in rapid succession
      await userEvent.click(button);
      await userEvent.click(button);
      await userEvent.click(button);
      
      // Should only call writeText once per click
      expect(mockWriteText).toHaveBeenCalledTimes(3);
    });
  });
});
