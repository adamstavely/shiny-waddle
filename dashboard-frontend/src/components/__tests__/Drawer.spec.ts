/**
 * Drawer Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import Drawer from '../Drawer.vue';

const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/targets', component: { template: '<div>Targets</div>' } },
      { path: '/tests', component: { template: '<div>Tests</div>' } },
    ],
  });
};

describe('Drawer', () => {
  it('renders drawer component', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.drawer').exists()).toBe(true);
  });

  it('has correct ARIA label', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    const drawer = wrapper.find('.drawer');
    expect(drawer.attributes('aria-label')).toBe('Category navigation');
  });

  it('renders toggle button', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.drawer-toggle').exists()).toBe(true);
  });

  it('toggles collapsed state when toggle button is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    const toggleButton = wrapper.find('.drawer-toggle');
    const initialCollapsed = wrapper.find('.drawer-collapsed').exists();

    await toggleButton.trigger('click');
    await wrapper.vm.$nextTick();

    const afterToggle = wrapper.find('.drawer-collapsed').exists();
    expect(afterToggle).toBe(!initialCollapsed);
  });

  it('shows navigation when not collapsed', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.drawer-nav').exists()).toBe(true);
  });

  it('hides navigation when collapsed', async () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    const toggleButton = wrapper.find('.drawer-toggle');
    await toggleButton.trigger('click');
    await wrapper.vm.$nextTick();

    const nav = wrapper.find('.drawer-nav');
    expect(nav.attributes('v-show') !== undefined || nav.isVisible() === false).toBe(true);
  });

  it('renders category items for targets category', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'targets',
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('[data-category="targets"]').exists()).toBe(true);
  });

  it('renders category items for test-design-library category', () => {
    const router = createTestRouter();
    const wrapper = mount(Drawer, {
      props: {
        activeCategory: 'test-design-library',
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('[data-category="test-design-library"]').exists()).toBe(true);
  });
});
