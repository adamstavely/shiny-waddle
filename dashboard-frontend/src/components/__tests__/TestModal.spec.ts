/**
 * TestModal Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import TestModal from '../TestModal.vue';
import axios from 'axios';

vi.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

const createTestRouter = () => {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/policies', component: { template: '<div>Policies</div>' } },
    ],
  });
};

describe('TestModal', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
  });

  it('renders modal when show is true', () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
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
    const wrapper = mount(TestModal, {
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

  it('displays "Create Test" title when testId is not provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
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

    expect(wrapper.text()).toContain('Create Test');
  });

  it('displays "Edit Test" title when testId is provided', () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
      props: {
        show: true,
        testId: 'test-123',
      },
      global: {
        plugins: [router],
        stubs: {
          RouterLink: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Edit Test');
  });

  it('emits close event when close button is clicked', async () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
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
    const wrapper = mount(TestModal, {
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

  it('renders basic information form section', () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
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

    expect(wrapper.text()).toContain('Basic Information');
  });

  it('renders test type selector', () => {
    const router = createTestRouter();
    const wrapper = mount(TestModal, {
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
