/**
 * EmptyState Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import EmptyState from '../EmptyState.vue';
import { FileText } from 'lucide-vue-next';

describe('EmptyState', () => {
  it('renders empty state component', () => {
    const wrapper = mount(EmptyState);

    expect(wrapper.find('.empty-state').exists()).toBe(true);
  });

  it('displays title when provided', () => {
    const wrapper = mount(EmptyState, {
      props: {
        title: 'No Items Found',
      },
    });

    expect(wrapper.find('.empty-state-title').text()).toBe('No Items Found');
  });

  it('displays description when provided', () => {
    const wrapper = mount(EmptyState, {
      props: {
        description: 'There are no items to display.',
      },
    });

    expect(wrapper.find('.empty-state-description').text()).toContain('There are no items to display.');
  });

  it('displays icon when provided', () => {
    const wrapper = mount(EmptyState, {
      props: {
        icon: FileText,
      },
    });

    expect(wrapper.find('.empty-state-icon').exists()).toBe(true);
  });

  it('renders default action button when showDefaultAction is true', () => {
    const wrapper = mount(EmptyState, {
      props: {
        showDefaultAction: true,
        actionLabel: 'Create Item',
      },
      global: {
        stubs: {
          BaseButton: {
            template: '<button class="base-button-stub">{{ label }}</button>',
            props: ['label', 'icon'],
          },
        },
      },
    });

    expect(wrapper.find('.base-button-stub').exists()).toBe(true);
    expect(wrapper.find('.base-button-stub').text()).toBe('Create Item');
  });

  it('renders custom action slot when provided', () => {
    const wrapper = mount(EmptyState, {
      slots: {
        actions: '<button class="custom-action">Custom Action</button>',
      },
      global: {
        stubs: {
          BaseButton: true,
        },
      },
    });

    expect(wrapper.find('.custom-action').exists()).toBe(true);
    expect(wrapper.find('.custom-action').text()).toBe('Custom Action');
  });

  it('emits action event when default action is clicked', async () => {
    const wrapper = mount(EmptyState, {
      props: {
        showDefaultAction: true,
        actionLabel: 'Create Item',
      },
      global: {
        stubs: {
          BaseButton: {
            template: '<button @click="$emit(\'click\')" class="base-button-stub">Create Item</button>',
          },
        },
      },
    });

    const button = wrapper.find('.base-button-stub');
    await button.trigger('click');

    // The component should emit 'action' when handleAction is called
    expect(wrapper.emitted('action')).toBeTruthy();
  });

  it('applies compact class when compact is true', () => {
    const wrapper = mount(EmptyState, {
      props: {
        compact: true,
      },
    });

    expect(wrapper.find('.empty-state-compact').exists()).toBe(true);
  });

  it('does not render actions section when no actions provided', () => {
    const wrapper = mount(EmptyState, {
      props: {
        showDefaultAction: false,
      },
      global: {
        stubs: {
          BaseButton: true,
        },
      },
    });

    expect(wrapper.find('.empty-state-actions').exists()).toBe(false);
  });

  it('renders all elements together', () => {
    const wrapper = mount(EmptyState, {
      props: {
        title: 'No Items',
        description: 'Create your first item to get started.',
        icon: FileText,
        showDefaultAction: true,
        actionLabel: 'Create Item',
      },
      global: {
        stubs: {
          BaseButton: {
            template: '<button class="base-button-stub">{{ label }}</button>',
            props: ['label', 'icon'],
          },
        },
      },
    });

    expect(wrapper.find('.empty-state-icon').exists()).toBe(true);
    expect(wrapper.find('.empty-state-title').text()).toBe('No Items');
    expect(wrapper.find('.empty-state-description').text()).toContain('Create your first item');
    expect(wrapper.find('.base-button-stub').exists()).toBe(true);
  });
});
