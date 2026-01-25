/**
 * Frontend Test Utilities
 * 
 * Common utilities for testing Vue components with Vitest and Vue Test Utils
 */

import { mount, VueWrapper, MountingOptions } from '@vue/test-utils';
import { ComponentPublicInstance } from 'vue';
import { Router } from 'vue-router';
import { createRouter, createWebHistory } from 'vue-router';

/**
 * Create a test router instance
 */
export function createTestRouter(routes: any[] = []) {
  return createRouter({
    history: createWebHistory(),
    routes: routes.length > 0 ? routes : [
      { path: '/', component: { template: '<div>Home</div>' } },
    ],
  });
}

/**
 * Mount component with common defaults
 */
export function mountComponent<T extends ComponentPublicInstance>(
  component: any,
  options: MountingOptions<any> = {}
): VueWrapper<T> {
  const defaultOptions: MountingOptions<any> = {
    global: {
      stubs: {
        RouterLink: true,
        RouterView: true,
      },
      mocks: {
        $router: createTestRouter(),
      },
      ...options.global,
    },
    ...options,
  };

  return mount(component, defaultOptions);
}

/**
 * Wait for next tick
 */
export async function nextTick() {
  return new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
}

/**
 * Mock router
 */
export function createMockRouter() {
  return {
    push: vi.fn(),
    replace: vi.fn(),
    go: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    currentRoute: {
      value: {
        path: '/',
        name: 'home',
        params: {},
        query: {},
        hash: '',
      },
    },
  } as any as Router;
}

/**
 * Mock accessibility utilities
 */
export const mockAccessibilityUtils = {
  generateId: vi.fn((prefix: string) => `${prefix}-${Math.random().toString(36).substr(2, 9)}`),
  trapFocus: vi.fn(() => () => {}),
  restoreFocus: vi.fn(),
};

/**
 * Common test data fixtures
 */
export const TestFixtures = {
  formData: {
    name: 'Test Form',
    description: 'Test description',
    email: 'test@example.com',
  },

  tableData: [
    { id: 1, name: 'Item 1', status: 'active' },
    { id: 2, name: 'Item 2', status: 'inactive' },
    { id: 3, name: 'Item 3', status: 'active' },
  ],

  tableColumns: [
    { key: 'id', label: 'ID' },
    { key: 'name', label: 'Name' },
    { key: 'status', label: 'Status' },
  ],
};
