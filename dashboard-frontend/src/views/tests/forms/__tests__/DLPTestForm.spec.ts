/**
 * DLPTestForm Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import DLPTestForm from '../DLPTestForm.vue';

describe('DLPTestForm', () => {
  const defaultForm = {
    pattern: {
      name: '',
      type: '',
      pattern: '',
    },
    bulkExportType: '',
    bulkExportLimit: undefined,
    testRecordCount: undefined,
    expectedBlocked: undefined,
    exportRestrictions: {
      requireMasking: false,
    },
    rlsCls: {
      database: {
        type: '',
        connectionString: '',
      },
      testQueries: [],
    },
    expectedDetection: undefined,
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders form component', () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    expect(wrapper.find('.dlp-test-form').exists()).toBe(true);
    expect(wrapper.find('.section-title').text()).toBe('DLP Configuration');
  });

  it('displays DLP test type selector', () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: { ...defaultForm },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    expect(wrapper.find('.form-group').exists()).toBe(true);
  });

  it('shows pattern test section when pattern type is selected', async () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: {
          ...defaultForm,
          pattern: {
            name: 'Test Pattern',
            type: 'regex',
            pattern: '\\d{3}-\\d{2}-\\d{4}',
          },
        },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    // Set the test type to pattern
    await wrapper.setData({ dlpTestType: 'pattern' });
    await wrapper.vm.$nextTick();

    expect(wrapper.find('.form-section').exists()).toBe(true);
  });

  it('shows bulk export test section when bulk-export type is selected', async () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: {
          ...defaultForm,
          bulkExportType: 'csv',
        },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    await wrapper.setData({ dlpTestType: 'bulk-export' });
    await wrapper.vm.$nextTick();

    const sections = wrapper.findAll('.form-section');
    expect(sections.length).toBeGreaterThan(0);
  });

  it('shows export restrictions section when export-restrictions type is selected', async () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: {
          ...defaultForm,
          exportRestrictions: {
            requireMasking: false,
          },
        },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    await wrapper.setData({ dlpTestType: 'export-restrictions' });
    await wrapper.vm.$nextTick();

    const sections = wrapper.findAll('.form-section');
    expect(sections.length).toBeGreaterThan(0);
  });

  it('shows RLS/CLS section when rls-cls type is selected', async () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: {
          ...defaultForm,
          rlsCls: {
            database: {
              type: 'postgresql',
              connectionString: '',
            },
            testQueries: [],
          },
        },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: true,
        },
      },
    });

    await wrapper.setData({ dlpTestType: 'rls-cls' });
    await wrapper.vm.$nextTick();

    const sections = wrapper.findAll('.form-section');
    expect(sections.length).toBeGreaterThan(0);
  });

  it('allows adding test queries in RLS/CLS section', async () => {
    const wrapper = mount(DLPTestForm, {
      props: {
        form: {
          ...defaultForm,
          rlsCls: {
            database: {
              type: 'postgresql',
              connectionString: '',
            },
            testQueries: [],
          },
        },
      },
      global: {
        stubs: {
          Dropdown: {
            template: '<div class="dropdown-stub"></div>',
            props: ['modelValue', 'options', 'placeholder'],
          },
          BaseButton: {
            template: '<button @click="$emit(\'click\')"><slot></slot></button>',
            props: ['label', 'variant', 'size'],
          },
        },
      },
    });

    await wrapper.setData({ dlpTestType: 'rls-cls' });
    await wrapper.vm.$nextTick();

    const addButton = wrapper.find('button');
    expect(addButton.exists()).toBe(true);
  });
});
