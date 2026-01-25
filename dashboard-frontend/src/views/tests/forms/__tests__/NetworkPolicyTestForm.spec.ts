/**
 * NetworkPolicyTestForm Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import NetworkPolicyTestForm from '../NetworkPolicyTestForm.vue';

describe('NetworkPolicyTestForm', () => {
  const defaultForm = {
    networkPolicy: {
      source: '',
      target: '',
      protocol: '',
      port: undefined,
      action: '',
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form component', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
        },
      },
    });

    expect(wrapper.find('.network-policy-test-form').exists()).toBe(true);
    expect(wrapper.find('.section-title').text()).toBe('Network Policy Configuration');
  });

  it('displays source and target input fields', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    const inputs = wrapper.findAll('input[type="text"]');
    expect(inputs.length).toBeGreaterThanOrEqual(2);
  });

  it('displays protocol dropdown', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
        },
      },
    });

    expect(wrapper.find('.dropdown-stub').exists()).toBe(true);
  });

  it('displays port input field', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    const portInput = wrapper.find('input[type="number"]');
    expect(portInput.exists()).toBe(true);
  });

  it('displays expected action dropdown', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
        },
      },
    });

    const dropdowns = wrapper.findAll('.dropdown-stub');
    expect(dropdowns.length).toBeGreaterThanOrEqual(2); // Protocol and action
  });

  it('shows help text for source field', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Source IP address or CIDR block');
  });

  it('shows help text for target field', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Target IP address or CIDR block');
  });

  it('shows help text for port field', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    expect(wrapper.text()).toContain('Optional port number');
  });

  it('initializes networkPolicy if not present', () => {
    const wrapper = mount(NetworkPolicyTestForm, {
      props: {
        form: {},
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    expect(wrapper.vm.form.networkPolicy).toBeDefined();
    expect(wrapper.vm.form.networkPolicy.source).toBe('');
    expect(wrapper.vm.form.networkPolicy.target).toBe('');
  });
});
