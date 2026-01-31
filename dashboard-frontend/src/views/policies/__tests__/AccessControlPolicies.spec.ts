/**
 * AccessControlPolicies Integration Tests
 * Tests data sync between tabs (Basic Info, Rules, Visual Builder, Code, Preview)
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createRouter, createWebHistory } from 'vue-router';
import AccessControlPolicies from '../AccessControlPolicies.vue';
import axios from 'axios';

vi.mock('axios');
const mockedAxios = axios as any;

describe('AccessControlPolicies - Data Sync Integration', () => {
  const router = createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: { template: '<div>Home</div>' } },
      { path: '/policies/:id', component: { template: '<div>Policy Detail</div>' } },
    ],
  });

  beforeEach(() => {
    vi.clearAllMocks();
    mockedAxios.get.mockResolvedValue({ data: [] });
    mockedAxios.post.mockResolvedValue({ data: { id: 'new-policy' } });
    mockedAxios.patch.mockResolvedValue({ data: {} });
  });

  it('syncs data from Visual Builder to Rules tab', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    // Open create modal
    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    // Set basic info
    wrapper.vm.policyForm = {
      name: 'Test Policy',
      description: 'Test Description',
      type: 'rbac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 100,
      rules: [],
      conditions: [],
    };

    // Switch to Visual Builder tab
    wrapper.vm.editorTab = 'visual';
    await wrapper.vm.$nextTick();

    // Update rules in Visual Builder
    const visualBuilderRules = [
      {
        id: 'rule-1',
        description: 'Visual Builder Rule',
        effect: 'allow',
        conditions: [{ key: 'subject.role', value: 'admin' }],
      },
    ];

    wrapper.vm.handleVisualBuilderUpdate(visualBuilderRules);
    await wrapper.vm.$nextTick();

    // Switch to Rules tab
    wrapper.vm.editorTab = 'rules';
    await wrapper.vm.$nextTick();

    // Verify rules are synced
    expect(wrapper.vm.policyForm.rules).toHaveLength(1);
    expect(wrapper.vm.policyForm.rules[0].id).toBe('rule-1');
    expect(wrapper.vm.policyForm.rules[0].description).toBe('Visual Builder Rule');
  });

  it('syncs data from Rules tab to Visual Builder', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    wrapper.vm.policyForm = {
      name: 'Test Policy',
      description: 'Test Description',
      type: 'rbac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 100,
      rules: [
        {
          id: 'rule-from-form',
          description: 'Form Rule',
          effect: 'allow',
          conditions: { 'subject.role': 'admin' },
        },
      ],
      conditions: [],
    };

    wrapper.vm.initializeConditionArrays();
    await wrapper.vm.$nextTick();

    // Switch to Visual Builder tab
    wrapper.vm.editorTab = 'visual';
    await wrapper.vm.$nextTick();

    // Verify Visual Builder receives the rules
    const visualBuilderRules = wrapper.vm.getVisualBuilderRules();
    expect(visualBuilderRules).toHaveLength(1);
    expect(visualBuilderRules[0].id).toBe('rule-from-form');
  });

  it('syncs data from Code tab to form', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    wrapper.vm.policyForm = {
      name: 'Test Policy',
      description: 'Test Description',
      type: 'rbac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 100,
      rules: [],
      conditions: [],
    };

    // Switch to Code tab
    wrapper.vm.editorTab = 'code';
    await wrapper.vm.$nextTick();

    // Update JSON in editor
    const jsonData = {
      name: 'Updated Name',
      version: '2.0.0',
      rules: [
        {
          id: 'json-rule',
          description: 'From JSON',
          effect: 'allow',
          conditions: { 'subject.role': 'admin' },
        },
      ],
    };

    wrapper.vm.handleJSONEditorUpdate(JSON.stringify(jsonData, null, 2));
    await wrapper.vm.$nextTick();

    // Verify form is updated
    expect(wrapper.vm.policyForm.name).toBe('Updated Name');
    expect(wrapper.vm.policyForm.version).toBe('2.0.0');
    expect(wrapper.vm.policyForm.rules).toHaveLength(1);
    expect(wrapper.vm.policyForm.rules[0].id).toBe('json-rule');
  });

  it('syncs data from form to Code tab', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    wrapper.vm.policyForm = {
      name: 'Test Policy',
      description: 'Test Description',
      type: 'rbac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 100,
      rules: [
        {
          id: 'form-rule',
          description: 'Form Rule',
          effect: 'allow',
          conditions: { 'subject.role': 'admin' },
        },
      ],
      conditions: [],
    };

    // Switch to Code tab
    wrapper.vm.editorTab = 'code';
    await wrapper.vm.$nextTick();

    // Verify JSON editor is updated
    const jsonValue = wrapper.vm.jsonEditorValue;
    const parsed = JSON.parse(jsonValue);
    expect(parsed.name).toBe('Test Policy');
    expect(parsed.rules).toHaveLength(1);
    expect(parsed.rules[0].id).toBe('form-rule');
  });

  it('maintains data consistency across all tabs', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    // Set initial data
    wrapper.vm.policyForm = {
      name: 'Consistency Test',
      description: 'Test',
      type: 'rbac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 100,
      rules: [
        {
          id: 'rule-1',
          description: 'Test Rule',
          effect: 'allow',
          conditions: { 'subject.role': 'admin' },
        },
      ],
      conditions: [],
    };

    wrapper.vm.initializeConditionArrays();

    // Navigate through all tabs
    const tabs = ['basic', 'rules', 'visual', 'code', 'preview'];

    for (const tab of tabs) {
      wrapper.vm.editorTab = tab as any;
      await wrapper.vm.$nextTick();

      // Verify data is still consistent
      expect(wrapper.vm.policyForm.name).toBe('Consistency Test');
      expect(wrapper.vm.policyForm.rules).toHaveLength(1);
      expect(wrapper.vm.policyForm.rules[0].id).toBe('rule-1');
    }
  });

  it('handles ABAC policy sync correctly', async () => {
    const wrapper = mount(AccessControlPolicies, {
      global: {
        plugins: [router],
      },
    });

    await wrapper.find('.btn-primary').trigger('click');
    await wrapper.vm.$nextTick();

    wrapper.vm.policyForm = {
      name: 'ABAC Policy',
      description: 'Test',
      type: 'abac',
      version: '1.0.0',
      status: 'draft',
      effect: 'allow',
      priority: 150,
      rules: [],
      conditions: [
        {
          attribute: 'subject.department',
          operator: 'equals',
          value: 'engineering',
        },
      ],
    };

    // Test Visual Builder sync
    wrapper.vm.editorTab = 'visual';
    await wrapper.vm.$nextTick();

    const visualBuilderData = wrapper.vm.getVisualBuilderRules();
    expect(visualBuilderData).toHaveLength(1);
    expect(visualBuilderData[0].attribute).toBe('subject.department');

    // Test Code tab sync
    wrapper.vm.editorTab = 'code';
    await wrapper.vm.$nextTick();

    const jsonValue = wrapper.vm.jsonEditorValue;
    const parsed = JSON.parse(jsonValue);
    expect(parsed.conditions).toHaveLength(1);
    expect(parsed.conditions[0].attribute).toBe('subject.department');
  });
});
