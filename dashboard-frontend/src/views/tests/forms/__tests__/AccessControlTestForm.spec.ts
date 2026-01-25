/**
 * AccessControlTestForm Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import AccessControlTestForm from '../AccessControlTestForm.vue';
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

describe('AccessControlTestForm', () => {
  const defaultForm = {
    policyId: undefined,
    inputs: {
      subject: {
        role: '',
        attributes: {},
      },
      resource: {
        id: '',
        type: '',
        sensitivity: '',
      },
      context: {
        ipAddress: '',
        timeOfDay: '',
        location: '',
      },
      action: '',
    },
    expected: {
      allowed: false,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form component', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.access-control-test-form').exists()).toBe(true);
    expect(wrapper.find('.section-title').text()).toBe('Access Control Configuration');
  });

  it('loads policies on mount', async () => {
    const router = createTestRouter();
    const mockPolicies = [
      { id: 'policy-1', name: 'Policy 1', type: 'rbac', description: 'Test policy' },
      { id: 'policy-2', name: 'Policy 2', type: 'abac', description: 'Another policy' },
    ];
    mockedAxios.get.mockResolvedValue({ data: mockPolicies });

    mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    expect(mockedAxios.get).toHaveBeenCalledWith('/api/policies');
  });

  it('displays policy filter dropdown', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.policy-filters').exists()).toBe(true);
  });

  it('displays role dropdown', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    const formGroups = wrapper.findAll('.form-group');
    const roleGroup = formGroups.find(group => 
      group.text().includes('Subject Role')
    );
    expect(roleGroup).toBeDefined();
  });

  it('displays resource configuration fields', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.resource-config').exists()).toBe(true);
  });

  it('displays context configuration fields', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    expect(wrapper.find('.context-config').exists()).toBe(true);
  });

  it('displays expected decision dropdown', () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    const formGroups = wrapper.findAll('.form-group');
    const decisionGroup = formGroups.find(group => 
      group.text().includes('Expected Decision')
    );
    expect(decisionGroup).toBeDefined();
  });

  it('shows loading state when loading policies', async () => {
    const router = createTestRouter();
    mockedAxios.get.mockImplementation(() => new Promise(() => {})); // Never resolves

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    await wrapper.vm.$nextTick();
    // Component should show loading state
    expect(wrapper.find('.loading-state').exists() || wrapper.text().includes('Loading')).toBeTruthy();
  });

  it('shows empty state when no policies available', async () => {
    const router = createTestRouter();
    mockedAxios.get.mockResolvedValue({ data: [] });

    const wrapper = mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: {
            template: '<div class="empty-state-stub"><slot name="actions"></slot></div>',
            props: ['title', 'description', 'showDefaultAction'],
          },
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    expect(wrapper.find('.empty-state-stub').exists()).toBe(true);
  });

  it('handles API error gracefully', async () => {
    const router = createTestRouter();
    mockedAxios.get.mockRejectedValue(new Error('API Error'));

    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    mount(AccessControlTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        plugins: [router],
        stubs: {
          Dropdown: true,
          StatusBadge: true,
          EmptyState: true,
          BaseButton: true,
          RouterLink: true,
        },
      },
    });

    await new Promise(resolve => setTimeout(resolve, 100));
    expect(mockedAxios.get).toHaveBeenCalled();
    consoleErrorSpy.mockRestore();
  });
});
