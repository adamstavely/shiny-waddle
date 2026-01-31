/**
 * PolicyVisualBuilder Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import PolicyVisualBuilder from '../PolicyVisualBuilder.vue';
import axios from 'axios';

vi.mock('axios');
const mockedAxios = axios as any;

describe('PolicyVisualBuilder', () => {
  const defaultProps = {
    policyType: 'rbac' as const,
    modelValue: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
  });

  it('renders component', () => {
    const wrapper = mount(PolicyVisualBuilder, {
      props: defaultProps,
    });

    expect(wrapper.exists()).toBe(true);
    expect(wrapper.find('.policy-visual-builder').exists()).toBe(true);
  });

  it('displays element palette for RBAC', () => {
    const wrapper = mount(PolicyVisualBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
      },
    });

    expect(wrapper.text()).toContain('Rule');
    expect(wrapper.text()).toContain('Condition');
  });

  it('displays element palette for ABAC', () => {
    const wrapper = mount(PolicyVisualBuilder, {
      props: {
        ...defaultProps,
        policyType: 'abac',
      },
    });

    expect(wrapper.text()).toContain('Condition');
    expect(wrapper.text()).toContain('Logical Operator');
  });

  it('loads templates on mount', async () => {
    const templates = [
      { id: '1', name: 'Template 1', type: 'rbac' },
      { id: '2', name: 'Template 2', type: 'rbac' },
    ];
    mockedAxios.get.mockResolvedValue({ data: templates });

    mount(PolicyVisualBuilder, {
      props: defaultProps,
    });

    await new Promise(resolve => setTimeout(resolve, 100));

    expect(mockedAxios.get).toHaveBeenCalledWith('/api/policies/templates', {
      params: { type: 'rbac' },
    });
  });

  it('emits update when rules change', async () => {
    const wrapper = mount(PolicyVisualBuilder, {
      props: defaultProps,
    });

    const newRules = [
      {
        id: 'rule-1',
        description: 'Test rule',
        effect: 'allow',
        conditions: [],
      },
    ];

    await wrapper.vm.handleRulesUpdate(newRules);

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([newRules]);
  });

  it('formats JSON correctly for RBAC', () => {
    const rules = [
      {
        id: 'rule-1',
        description: 'Test',
        effect: 'allow',
        conditions: [{ key: 'subject.role', value: 'admin' }],
      },
    ];

    const wrapper = mount(PolicyVisualBuilder, {
      props: {
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    const jsonText = wrapper.find('.json-preview').text();
    expect(jsonText).toContain('rule-1');
    expect(jsonText).toContain('allow');
  });

  it('formats JSON correctly for ABAC', () => {
    const conditions = [
      {
        attribute: 'subject.department',
        operator: 'equals',
        value: 'engineering',
      },
    ];

    const wrapper = mount(PolicyVisualBuilder, {
      props: {
        policyType: 'abac',
        modelValue: conditions,
      },
    });

    const jsonText = wrapper.find('.json-preview').text();
    expect(jsonText).toContain('subject.department');
  });

  it('clears all rules when clearAll is called', async () => {
    const wrapper = mount(PolicyVisualBuilder, {
      props: {
        ...defaultProps,
        modelValue: [
          {
            id: 'rule-1',
            description: 'Test',
            effect: 'allow',
            conditions: [],
          },
        ],
      },
    });

    await wrapper.find('.btn-secondary').trigger('click');

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([[]]);
  });

  it('copies JSON to clipboard', async () => {
    const writeTextSpy = vi.fn();
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextSpy,
      },
    });

    const wrapper = mount(PolicyVisualBuilder, {
      props: defaultProps,
    });

    const copyButton = wrapper.findAll('.btn-secondary').find(
      btn => btn.text() === 'Copy JSON'
    );
    
    if (copyButton) {
      await copyButton.trigger('click');
      expect(writeTextSpy).toHaveBeenCalled();
    }
  });

  it('applies template when selected', async () => {
    const templates = [
      {
        id: 'template-1',
        name: 'Test Template',
        type: 'rbac',
        template: {
          rules: [
            {
              id: 'rule-from-template',
              description: 'From template',
              effect: 'allow',
              conditions: {},
            },
          ],
        },
      },
    ];
    mockedAxios.get.mockResolvedValue({ data: templates });
    mockedAxios.post.mockResolvedValue({});

    const wrapper = mount(PolicyVisualBuilder, {
      props: defaultProps,
    });

    await new Promise(resolve => setTimeout(resolve, 100));

    // Simulate template selection
    await wrapper.vm.applyTemplate('template-1');

    expect(mockedAxios.post).toHaveBeenCalledWith(
      '/api/policies/templates/template-1/use'
    );
  });
});
