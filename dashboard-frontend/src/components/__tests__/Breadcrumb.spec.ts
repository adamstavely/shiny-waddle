/**
 * Breadcrumb Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import Breadcrumb, { type BreadcrumbItem } from '../Breadcrumb.vue';

const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: { template: '<div>Home</div>' } },
      { path: '/tests', component: { template: '<div>Tests</div>' } },
      { path: '/tests/create', component: { template: '<div>Create Test</div>' } },
    ],
  });
};

describe('Breadcrumb', () => {
  const items: BreadcrumbItem[] = [
    { label: 'Home', to: '/' },
    { label: 'Tests', to: '/tests' },
    { label: 'Create Test' },
  ];

  it('renders breadcrumb navigation', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.breadcrumb').exists()).toBe(true);
    expect(wrapper.find('.breadcrumb-list').exists()).toBe(true);
  });

  it('has correct ARIA label', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    const breadcrumb = wrapper.find('.breadcrumb');
    expect(breadcrumb.attributes('aria-label')).toBe('Breadcrumb');
  });

  it('renders all breadcrumb items', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    const breadcrumbItems = wrapper.findAll('.breadcrumb-item');
    expect(breadcrumbItems.length).toBe(3);
  });

  it('renders links for non-active items', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    const links = wrapper.findAll('.breadcrumb-link');
    expect(links.length).toBe(2); // First two items have links
  });

  it('renders current item without link', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    const currentItem = wrapper.find('.breadcrumb-current');
    expect(currentItem.exists()).toBe(true);
    expect(currentItem.text()).toBe('Create Test');
  });

  it('applies is-active class to last item', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items,
      },
      global: {
        plugins: [router],
      },
    });

    const breadcrumbItems = wrapper.findAll('.breadcrumb-item');
    const lastItem = breadcrumbItems[breadcrumbItems.length - 1];
    expect(lastItem.classes()).toContain('is-active');
  });

  it('handles single item breadcrumb', () => {
    const router = createTestRouter();
    const singleItem: BreadcrumbItem[] = [
      { label: 'Home' },
    ];

    const wrapper = mount(Breadcrumb, {
      props: {
        items: singleItem,
      },
      global: {
        plugins: [router],
      },
    });

    const breadcrumbItems = wrapper.findAll('.breadcrumb-item');
    expect(breadcrumbItems.length).toBe(1);
    expect(breadcrumbItems[0].classes()).toContain('is-active');
  });

  it('handles empty items array', () => {
    const router = createTestRouter();
    const wrapper = mount(Breadcrumb, {
      props: {
        items: [],
      },
      global: {
        plugins: [router],
      },
    });

    const breadcrumbItems = wrapper.findAll('.breadcrumb-item');
    expect(breadcrumbItems.length).toBe(0);
  });

  it('renders items without to property as current', () => {
    const router = createTestRouter();
    const itemsWithoutTo: BreadcrumbItem[] = [
      { label: 'Home' },
      { label: 'Tests' },
    ];

    const wrapper = mount(Breadcrumb, {
      props: {
        items: itemsWithoutTo,
      },
      global: {
        plugins: [router],
      },
    });

    const links = wrapper.findAll('.breadcrumb-link');
    expect(links.length).toBe(0); // No links since no 'to' properties
  });
});
