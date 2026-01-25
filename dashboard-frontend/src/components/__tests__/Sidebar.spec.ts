/**
 * Sidebar Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import Sidebar from '../Sidebar.vue';

const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/dashboard', component: { template: '<div>Dashboard</div>' } },
      { path: '/tests', component: { template: '<div>Tests</div>' } },
      { path: '/admin', component: { template: '<div>Admin</div>' } },
    ],
  });
};

describe('Sidebar', () => {
  it('renders navigation items', () => {
    const router = createTestRouter();
    const wrapper = mount(Sidebar, {
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.sidebar').exists()).toBe(true);
    expect(wrapper.find('.sidebar-nav').exists()).toBe(true);
    expect(wrapper.find('.nav-items-container').exists()).toBe(true);
  });

  it('has correct ARIA label', () => {
    const router = createTestRouter();
    const wrapper = mount(Sidebar, {
      global: {
        plugins: [router],
      },
    });

    const sidebar = wrapper.find('.sidebar');
    expect(sidebar.attributes('aria-label')).toBe('Main navigation');
  });

  it('renders admin section at bottom', () => {
    const router = createTestRouter();
    const wrapper = mount(Sidebar, {
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.nav-admin-section').exists()).toBe(true);
  });

  it('highlights active route', async () => {
    const router = createTestRouter();
    await router.push('/dashboard');
    
    const wrapper = mount(Sidebar, {
      global: {
        plugins: [router],
      },
    });

    await router.isReady();
    // The active item should have nav-item-active class
    const activeItems = wrapper.findAll('.nav-item-active');
    expect(activeItems.length).toBeGreaterThan(0);
  });
});
