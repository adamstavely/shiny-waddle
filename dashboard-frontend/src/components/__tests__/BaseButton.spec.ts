/**
 * BaseButton Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import BaseButton from '../BaseButton.vue';
import { Save } from 'lucide-vue-next';

describe('BaseButton', () => {
  it('renders button with label', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Click Me',
      },
    });

    expect(wrapper.find('.base-button').exists()).toBe(true);
    expect(wrapper.find('.btn-label').text()).toBe('Click Me');
  });

  it('renders button without label (icon only)', () => {
    const wrapper = mount(BaseButton, {
      props: {
        icon: Save,
        iconOnly: true,
      },
    });

    expect(wrapper.find('.base-button').exists()).toBe(true);
    expect(wrapper.find('.btn-icon-only').exists()).toBe(true);
    expect(wrapper.find('.btn-label').exists()).toBe(false);
  });

  it('applies primary variant by default', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
      },
    });

    expect(wrapper.find('.btn-primary').exists()).toBe(true);
  });

  it('applies correct variant classes', () => {
    const variants = ['primary', 'secondary', 'ghost', 'danger', 'success'] as const;

    variants.forEach((variant) => {
      const wrapper = mount(BaseButton, {
        props: {
          label: 'Button',
          variant,
        },
      });

      expect(wrapper.find(`.btn-${variant}`).exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('applies correct size classes', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      const wrapper = mount(BaseButton, {
        props: {
          label: 'Button',
          size,
        },
      });

      expect(wrapper.find(`.btn-${size}`).exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('renders icon when provided', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Save',
        icon: Save,
      },
    });

    expect(wrapper.find('.btn-icon').exists()).toBe(true);
  });

  it('positions icon on left by default', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Save',
        icon: Save,
      },
    });

    expect(wrapper.find('.icon-left').exists()).toBe(true);
  });

  it('positions icon on right when iconRight is true', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Next',
        icon: Save,
        iconRight: true,
      },
    });

    expect(wrapper.find('.icon-right').exists()).toBe(true);
  });

  it('disables button when disabled prop is true', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        disabled: true,
      },
    });

    const button = wrapper.find('.base-button');
    expect(button.attributes('disabled')).toBeDefined();
  });

  it('disables button when loading prop is true', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        loading: true,
      },
    });

    const button = wrapper.find('.base-button');
    expect(button.attributes('disabled')).toBeDefined();
    expect(wrapper.find('.btn-loading').exists()).toBe(true);
  });

  it('shows loading spinner when loading', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        loading: true,
      },
    });

    expect(wrapper.find('.btn-spinner').exists()).toBe(true);
  });

  it('hides icon when loading', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        icon: Save,
        loading: true,
      },
    });

    // Icon should not be visible when loading
    const icon = wrapper.find('.btn-icon');
    expect(icon.exists()).toBe(false);
  });

  it('applies full width class when fullWidth is true', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        fullWidth: true,
      },
    });

    expect(wrapper.find('.btn-full-width').exists()).toBe(true);
  });

  it('emits click event when clicked', async () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeTruthy();
    expect(wrapper.emitted('click')?.length).toBe(1);
  });

  it('does not emit click when disabled', async () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        disabled: true,
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeFalsy();
  });

  it('does not emit click when loading', async () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
        loading: true,
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeFalsy();
  });

  it('renders as anchor tag when tag is "a"', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Link',
        tag: 'a',
        href: '/test',
      },
    });

    expect(wrapper.find('a').exists()).toBe(true);
    expect(wrapper.find('button').exists()).toBe(false);
  });

  it('renders as button tag by default', () => {
    const wrapper = mount(BaseButton, {
      props: {
        label: 'Button',
      },
    });

    expect(wrapper.find('button').exists()).toBe(true);
  });

  it('applies correct type attribute', () => {
    const types = ['button', 'submit', 'reset'] as const;

    types.forEach((type) => {
      const wrapper = mount(BaseButton, {
        props: {
          label: 'Button',
          type,
        },
      });

      expect(wrapper.find('button').attributes('type')).toBe(type);
      wrapper.unmount();
    });
  });

  it('renders slot content', () => {
    const wrapper = mount(BaseButton, {
      slots: {
        default: '<span>Custom Content</span>',
      },
    });

    expect(wrapper.text()).toContain('Custom Content');
  });
});
