/**
 * TestHarnessModal Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import TestHarnessModal from '../TestHarnessModal.vue';
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

describe('TestHarnessModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
  });

  it('renders modal when show is true', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(true);
    expect(wrapper.find('.modal-content').exists()).toBe(true);
  });

  it('does not render when show is false', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: false,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(false);
  });

  it('displays "Create Test Harness" title when editingHarness is not provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Create Test Harness');
  });

  it('displays "Edit Test Harness" title when editingHarness is provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
        editingHarness: { id: 'harness-1', name: 'Test Harness' },
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Edit Test Harness');
  });

  it('renders name input field', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    const nameInput = wrapper.find('input[type="text"]');
    expect(nameInput.exists()).toBe(true);
  });

  it('renders description textarea', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    const textarea = wrapper.find('textarea');
    expect(textarea.exists()).toBe(true);
  });

  it('renders domain selector', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    const select = wrapper.find('select');
    expect(select.exists()).toBe(true);
    expect(select.text()).toContain('Select a domain...');
  });

  it('renders test suites section', () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Test Suites');
  });

  it('shows domain filter info when domain is selected', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    await wrapper.setData({ form: { domain: 'api_security' } });
    await wrapper.vm.$nextTick();

    expect(wrapper.text()).toContain('Showing only suites with domain');
  });

  it('emits close event when close button is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    const closeButton = wrapper.find('.modal-close');
    await closeButton.trigger('click');

    expect(wrapper.emitted('close')).toBeTruthy();
  });

  it('loads test suites on mount', async () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    mount(TestHarnessModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    expect(mockedAxios.get).toHaveBeenCalled();
  });
});
