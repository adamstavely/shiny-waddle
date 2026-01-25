/**
 * BaseCard Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import BaseCard from '../BaseCard.vue';
import { FileText } from 'lucide-vue-next';

describe('BaseCard', () => {
  it('renders card component', () => {
    const wrapper = mount(BaseCard);

    expect(wrapper.find('.base-card').exists()).toBe(true);
  });

  it('displays title when provided', () => {
    const wrapper = mount(BaseCard, {
      props: {
        title: 'Test Card',
      },
    });

    expect(wrapper.find('.card-title').text()).toBe('Test Card');
  });

  it('displays icon when provided', () => {
    const wrapper = mount(BaseCard, {
      props: {
        icon: FileText,
      },
    });

    expect(wrapper.find('.card-icon').exists()).toBe(true);
  });

  it('displays both title and icon', () => {
    const wrapper = mount(BaseCard, {
      props: {
        title: 'Test Card',
        icon: FileText,
      },
    });

    expect(wrapper.find('.card-title').text()).toBe('Test Card');
    expect(wrapper.find('.card-icon').exists()).toBe(true);
  });

  it('renders default slot content', () => {
    const wrapper = mount(BaseCard, {
      slots: {
        default: '<p>Card content</p>',
      },
    });

    expect(wrapper.find('.card-body').exists()).toBe(true);
    expect(wrapper.text()).toContain('Card content');
  });

  it('renders header slot when provided', () => {
    const wrapper = mount(BaseCard, {
      slots: {
        header: '<div class="custom-header">Custom Header</div>',
      },
    });

    expect(wrapper.find('.custom-header').exists()).toBe(true);
  });

  it('renders footer slot when provided', () => {
    const wrapper = mount(BaseCard, {
      slots: {
        footer: '<div class="custom-footer">Custom Footer</div>',
      },
    });

    expect(wrapper.find('.custom-footer').exists()).toBe(true);
  });

  it('applies default variant class', () => {
    const wrapper = mount(BaseCard);

    expect(wrapper.find('.card-default').exists()).toBe(true);
  });

  it('applies correct variant classes', () => {
    const variants = ['default', 'alt', 'elevated'] as const;

    variants.forEach((variant) => {
      const wrapper = mount(BaseCard, {
        props: {
          variant,
        },
      });

      expect(wrapper.find(`.card-${variant}`).exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('applies clickable class when clickable is true', () => {
    const wrapper = mount(BaseCard, {
      props: {
        clickable: true,
      },
    });

    expect(wrapper.find('.card-clickable').exists()).toBe(true);
  });

  it('emits click event when clicked and clickable is true', async () => {
    const wrapper = mount(BaseCard, {
      props: {
        clickable: true,
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeTruthy();
    expect(wrapper.emitted('click')?.length).toBe(1);
  });

  it('does not emit click when clickable is false', async () => {
    const wrapper = mount(BaseCard, {
      props: {
        clickable: false,
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeFalsy();
  });

  it('does not emit click when disabled', async () => {
    const wrapper = mount(BaseCard, {
      props: {
        clickable: true,
        disabled: true,
      },
    });

    await wrapper.trigger('click');
    expect(wrapper.emitted('click')).toBeFalsy();
  });

  it('applies disabled class when disabled is true', () => {
    const wrapper = mount(BaseCard, {
      props: {
        disabled: true,
      },
    });

    expect(wrapper.find('.card-disabled').exists()).toBe(true);
  });

  it('does not render header when no title, icon, or header slot', () => {
    const wrapper = mount(BaseCard);

    expect(wrapper.find('.card-header').exists()).toBe(false);
  });

  it('renders header when title is provided', () => {
    const wrapper = mount(BaseCard, {
      props: {
        title: 'Test Card',
      },
    });

    expect(wrapper.find('.card-header').exists()).toBe(true);
  });

  it('renders header when icon is provided', () => {
    const wrapper = mount(BaseCard, {
      props: {
        icon: FileText,
      },
    });

    expect(wrapper.find('.card-header').exists()).toBe(true);
  });
});
