/**
 * APISecurityTestForm Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import APISecurityTestForm from '../APISecurityTestForm.vue';

describe('APISecurityTestForm', () => {
  const defaultForm = {
    apiVersion: {
      version: '',
      endpoint: '',
      deprecated: false,
      deprecationDate: undefined,
      sunsetDate: undefined,
    },
    graphql: {
      endpoint: '',
      schema: '',
      testType: 'depth',
      maxDepth: undefined,
      maxComplexity: undefined,
      introspectionEnabled: false,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form component', () => {
    const wrapper = mount(APISecurityTestForm, {
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

    expect(wrapper.find('.api-security-test-form').exists()).toBe(true);
    expect(wrapper.find('.section-title').text()).toBe('API Security Configuration');
  });

  it('displays API security test type selector', () => {
    const wrapper = mount(APISecurityTestForm, {
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

    expect(wrapper.find('.form-group').exists()).toBe(true);
  });

  it('shows API versioning section when apiVersion type is selected', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          apiVersion: {
            version: 'v1',
            endpoint: '/api/v1/users',
            deprecated: false,
          },
        },
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

    await wrapper.setData({ apiSecuritySubType: 'apiVersion' });
    await wrapper.vm.$nextTick();

    const sections = wrapper.findAll('.form-section');
    expect(sections.length).toBeGreaterThan(0);
  });

  it('shows deprecation fields when deprecated checkbox is checked', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          apiVersion: {
            version: 'v1',
            endpoint: '/api/v1/users',
            deprecated: true,
          },
        },
      },
      global: {
        stubs: {
          Dropdown: true,
        },
      },
    });

    await wrapper.setData({ apiSecuritySubType: 'apiVersion' });
    await wrapper.vm.$nextTick();

    const dateInputs = wrapper.findAll('input[type="date"]');
    expect(dateInputs.length).toBeGreaterThanOrEqual(2); // Deprecation and sunset dates
  });

  it('shows GraphQL section when graphql type is selected', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          graphql: {
            endpoint: '/graphql',
            schema: 'type Query { users: [User] }',
            testType: 'depth',
            maxDepth: 10,
            introspectionEnabled: false,
          },
        },
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

    await wrapper.setData({ apiSecuritySubType: 'graphql' });
    await wrapper.vm.$nextTick();

    const sections = wrapper.findAll('.form-section');
    expect(sections.length).toBeGreaterThan(0);
  });

  it('shows max depth field when GraphQL test type is depth', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          graphql: {
            endpoint: '/graphql',
            schema: '',
            testType: 'depth',
            maxDepth: 10,
          },
        },
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

    await wrapper.setData({ apiSecuritySubType: 'graphql' });
    await wrapper.vm.$nextTick();

    const numberInputs = wrapper.findAll('input[type="number"]');
    expect(numberInputs.length).toBeGreaterThan(0);
  });

  it('shows max complexity field when GraphQL test type is complexity', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          graphql: {
            endpoint: '/graphql',
            schema: '',
            testType: 'complexity',
            maxComplexity: 100,
          },
        },
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

    await wrapper.setData({ apiSecuritySubType: 'graphql' });
    await wrapper.vm.$nextTick();

    const numberInputs = wrapper.findAll('input[type="number"]');
    expect(numberInputs.length).toBeGreaterThan(0);
  });

  it('shows introspection checkbox when GraphQL test type is introspection', async () => {
    const wrapper = mount(APISecurityTestForm, {
      props: {
        form: {
          ...defaultForm,
          graphql: {
            endpoint: '/graphql',
            schema: '',
            testType: 'introspection',
            introspectionEnabled: false,
          },
        },
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

    await wrapper.setData({ apiSecuritySubType: 'graphql' });
    await wrapper.vm.$nextTick();

    const checkboxes = wrapper.findAll('input[type="checkbox"]');
    expect(checkboxes.length).toBeGreaterThan(0);
  });
});
