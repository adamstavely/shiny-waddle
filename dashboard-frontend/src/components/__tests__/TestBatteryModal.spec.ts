/**
 * TestBatteryModal Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import TestBatteryModal from '../TestBatteryModal.vue';
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

describe('TestBatteryModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
  });

  it('renders modal when show is true', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
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
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: false,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(false);
  });

  it('displays "Create Test Battery" title when editingBattery is not provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Create Test Battery');
  });

  it('displays "Edit Test Battery" title when editingBattery is provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: true,
        editingBattery: { id: 'battery-1', name: 'Test Battery' },
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Edit Test Battery');
  });

  it('renders name input field', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
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
    const wrapper = mount(TestBatteryModal, {
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

  it('renders execution configuration section', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Execution Configuration');
  });

  it('renders execution mode selector', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    const select = wrapper.find('select');
    expect(select.exists()).toBe(true);
    expect(select.text()).toContain('Sequential');
    expect(select.text()).toContain('Parallel');
  });

  it('renders test harnesses section', () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
      props: {
        show: true,
      },
      global: {
        plugins: [router],
      },
    });

    expect(wrapper.text()).toContain('Test Harnesses');
  });

  it('emits close event when close button is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestBatteryModal, {
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

  it('loads harnesses on mount', async () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    mount(TestBatteryModal, {
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
