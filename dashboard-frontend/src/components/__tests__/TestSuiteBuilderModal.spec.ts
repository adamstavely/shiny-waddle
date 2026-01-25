/**
 * TestSuiteBuilderModal Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import TestSuiteBuilderModal from '../TestSuiteBuilderModal.vue';
import axios from 'axios';

vi.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: { template: '<div>Home</div>' } },
    ],
  });
};

describe('TestSuiteBuilderModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
  });

  it('renders modal when show is true', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(true);
    expect(wrapper.find('.modal-content').exists()).toBe(true);
  });

  it('does not render when show is false', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: false,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(false);
  });

  it('displays "Create Test Suite" title when editingSuite is not provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Create Test Suite');
  });

  it('displays "Edit Test Suite" title when editingSuite is provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
        editingSuite: { id: 'suite-1', name: 'Test Suite' },
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Edit Test Suite');
  });

  it('renders tab navigation', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.builder-tabs').exists()).toBe(true);
  });

  it('renders basic information tab', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Test Suite Name');
  });

  it('shows TypeScript warning when editing TypeScript suite', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
        editingSuite: {
          id: 'suite-1',
          name: 'Test Suite',
          _isTypeScript: true,
        },
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.typescript-warning').exists()).toBe(true);
    expect(wrapper.text()).toContain('TypeScript Source File');
  });

  it('emits close event when close button is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    const closeButton = wrapper.find('.modal-close');
    await closeButton.trigger('click');

    expect(wrapper.emitted('close')).toBeTruthy();
  });

  it('emits close event when overlay is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    const overlay = wrapper.find('.modal-overlay');
    await overlay.trigger('click');

    expect(wrapper.emitted('close')).toBeTruthy();
  });

  it('renders test type selector', () => {
    const router = createTestRouter();
    const wrapper = mount(TestSuiteBuilderModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    const select = wrapper.find('select');
    expect(select.exists()).toBe(true);
    expect(select.text()).toContain('Select a test type...');
  });
});
