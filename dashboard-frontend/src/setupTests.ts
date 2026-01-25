/**
 * Vitest Setup File
 * 
 * Configures global test utilities and mocks
 */

import { vi } from 'vitest';

// Mock accessibility utilities
vi.mock('./utils/accessibility', () => ({
  generateId: vi.fn((prefix: string) => `${prefix}-${Math.random().toString(36).substr(2, 9)}`),
  trapFocus: vi.fn(() => () => {}),
  restoreFocus: vi.fn(),
  announceToScreenReader: vi.fn(),
}));

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});

// Mock ResizeObserver
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));
