/**
 * PolicyRuleBuilder Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import PolicyRuleBuilder from '../PolicyRuleBuilder.vue';

describe('PolicyRuleBuilder', () => {
  const defaultProps = {
    policyType: 'rbac' as const,
    modelValue: [],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders component', () => {
    const wrapper = mount(PolicyRuleBuilder, {
      props: defaultProps,
    });

    expect(wrapper.exists()).toBe(true);
    expect(wrapper.find('.policy-rule-builder').exists()).toBe(true);
  });

  it('displays empty state when no rules', () => {
    const wrapper = mount(PolicyRuleBuilder, {
      props: defaultProps,
    });

    expect(wrapper.text()).toContain('No rules yet');
  });

  it('adds RBAC rule when add button clicked', async () => {
    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
      },
    });

    const addButton = wrapper.find('.btn-add-rule');
    await addButton.trigger('click');

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    const emittedValue = wrapper.emitted('update:modelValue')?.[0]?.[0];
    expect(emittedValue).toHaveLength(1);
    expect(emittedValue?.[0]).toHaveProperty('id');
    expect(emittedValue?.[0]).toHaveProperty('effect', 'allow');
  });

  it('adds ABAC condition when add button clicked', async () => {
    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'abac',
      },
    });

    const addButton = wrapper.find('.btn-add-rule');
    await addButton.trigger('click');

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    const emittedValue = wrapper.emitted('update:modelValue')?.[0]?.[0];
    expect(emittedValue).toHaveLength(1);
    expect(emittedValue?.[0]).toHaveProperty('attribute');
    expect(emittedValue?.[0]).toHaveProperty('operator', 'equals');
  });

  it('removes rule when remove button clicked', async () => {
    const rules = [
      {
        id: 'rule-1',
        description: 'Test',
        effect: 'allow' as const,
        conditions: [],
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    const removeButton = wrapper.find('.btn-remove');
    await removeButton.trigger('click');

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    const emittedValue = wrapper.emitted('update:modelValue')?.[0]?.[0];
    expect(emittedValue).toHaveLength(0);
  });

  it('displays rule cards for RBAC', () => {
    const rules = [
      {
        id: 'rule-1',
        description: 'Test rule',
        effect: 'allow' as const,
        conditions: [],
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    expect(wrapper.text()).toContain('Rule 1');
    expect(wrapper.find('input[placeholder*="admin-full-access"]').exists()).toBe(true);
  });

  it('displays condition cards for ABAC', () => {
    const conditions = [
      {
        attribute: 'subject.department',
        operator: 'equals',
        value: 'engineering',
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'abac',
        modelValue: conditions,
      },
    });

    expect(wrapper.text()).toContain('Condition 1');
  });

  it('adds condition to RBAC rule', async () => {
    const rules = [
      {
        id: 'rule-1',
        description: 'Test',
        effect: 'allow' as const,
        conditions: [],
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    const addConditionButton = wrapper.find('.btn-add-condition');
    await addConditionButton.trigger('click');

    // Check that condition was added to the rule
    const updatedRules = wrapper.vm.rules;
    expect(updatedRules[0].conditions).toHaveLength(1);
  });

  it('removes condition from RBAC rule', async () => {
    const rules = [
      {
        id: 'rule-1',
        description: 'Test',
        effect: 'allow' as const,
        conditions: [
          { key: 'subject.role', value: 'admin' },
        ],
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    const removeConditionButton = wrapper.find('.btn-remove-small');
    await removeConditionButton.trigger('click');

    const updatedRules = wrapper.vm.rules;
    expect(updatedRules[0].conditions).toHaveLength(0);
  });

  it('updates rule properties when input changes', async () => {
    const rules = [
      {
        id: 'rule-1',
        description: '',
        effect: 'allow' as const,
        conditions: [],
      },
    ];

    const wrapper = mount(PolicyRuleBuilder, {
      props: {
        ...defaultProps,
        policyType: 'rbac',
        modelValue: rules,
      },
    });

    const descriptionInput = wrapper.find('textarea[placeholder*="Describe"]');
    await descriptionInput.setValue('Updated description');

    expect(wrapper.vm.rules[0].description).toBe('Updated description');
  });
});
