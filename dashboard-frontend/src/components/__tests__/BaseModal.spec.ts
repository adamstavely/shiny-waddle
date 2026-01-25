/**
 * BaseModal Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import BaseModal from '../BaseModal.vue';
import { nextTick } from '../../test-utils';

describe('BaseModal', () => {
  beforeEach(() => {
    // Reset body overflow before each test
    document.body.style.overflow = '';
  });

  afterEach(() => {
    // Clean up body overflow after each test
    document.body.style.overflow = '';
  });

  it('renders when isOpen is true', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
    });

    await nextTick();
    expect(wrapper.find('.modal-overlay').exists()).toBe(true);
    expect(wrapper.find('.modal-content').exists()).toBe(true);
  });

  it('does not render when isOpen is false', () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: false,
      },
    });

    expect(wrapper.find('.modal-overlay').exists()).toBe(false);
  });

  it('displays title when provided', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        title: 'Test Modal',
      },
    });

    await nextTick();
    expect(wrapper.find('.modal-title').text()).toBe('Test Modal');
  });

  it('renders close button when showClose is true', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        showClose: true,
      },
    });

    await nextTick();
    const closeButton = wrapper.find('.modal-close');
    expect(closeButton.exists()).toBe(true);
  });

  it('hides close button when showClose is false', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        showClose: false,
      },
    });

    await nextTick();
    expect(wrapper.find('.modal-close').exists()).toBe(false);
  });

  it('emits close event when close button is clicked', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        showClose: true,
      },
    });

    await nextTick();
    const closeButton = wrapper.find('.modal-close');
    await closeButton.trigger('click');

    expect(wrapper.emitted('close')).toBeTruthy();
    expect(wrapper.emitted('update:isOpen')).toBeTruthy();
    expect(wrapper.emitted('update:isOpen')?.[0]).toEqual([false]);
  });

  it('emits close event when overlay is clicked and closeOnOverlayClick is true', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        closeOnOverlayClick: true,
      },
    });

    await nextTick();
    const overlay = wrapper.find('.modal-overlay');
    await overlay.trigger('click');

    expect(wrapper.emitted('close')).toBeTruthy();
    expect(wrapper.emitted('update:isOpen')).toBeTruthy();
  });

  it('does not close when overlay is clicked and closeOnOverlayClick is false', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        closeOnOverlayClick: false,
      },
    });

    await nextTick();
    const overlay = wrapper.find('.modal-overlay');
    await overlay.trigger('click');

    expect(wrapper.emitted('close')).toBeFalsy();
  });

  it('does not close when modal content is clicked', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        closeOnOverlayClick: true,
      },
    });

    await nextTick();
    const modalContent = wrapper.find('.modal-content');
    await modalContent.trigger('click');

    expect(wrapper.emitted('close')).toBeFalsy();
  });

  it('applies correct size class', async () => {
    const sizes = ['sm', 'md', 'lg', 'xl'] as const;

    for (const size of sizes) {
      const wrapper = mount(BaseModal, {
        props: {
          isOpen: true,
          size,
        },
      });

      await nextTick();
      expect(wrapper.find(`.modal-${size}`).exists()).toBe(true);
      wrapper.unmount();
    }
  });

  it('applies fullscreen class when fullscreen is true', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        fullscreen: true,
      },
    });

    await nextTick();
    expect(wrapper.find('.modal-fullscreen').exists()).toBe(true);
  });

  it('renders slot content in modal body', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
      slots: {
        default: '<div class="test-content">Test Content</div>',
      },
    });

    await nextTick();
    expect(wrapper.find('.test-content').exists()).toBe(true);
    expect(wrapper.find('.test-content').text()).toBe('Test Content');
  });

  it('renders header slot when provided', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
      slots: {
        header: '<div class="custom-header">Custom Header</div>',
      },
    });

    await nextTick();
    expect(wrapper.find('.custom-header').exists()).toBe(true);
  });

  it('renders footer slot when provided', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
      slots: {
        footer: '<div class="custom-footer">Custom Footer</div>',
      },
    });

    await nextTick();
    expect(wrapper.find('.custom-footer').exists()).toBe(true);
  });

  it('has correct ARIA attributes', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
        title: 'Test Modal',
        description: 'Test description',
      },
    });

    await nextTick();
    const overlay = wrapper.find('.modal-overlay');
    expect(overlay.attributes('role')).toBe('dialog');
    expect(overlay.attributes('aria-modal')).toBe('true');
    expect(overlay.attributes('aria-labelledby')).toBeDefined();
    expect(overlay.attributes('aria-describedby')).toBeDefined();
  });

  it('prevents body scroll when open', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
    });

    await nextTick();
    expect(document.body.style.overflow).toBe('hidden');
  });

  it('restores body scroll when closed', async () => {
    const wrapper = mount(BaseModal, {
      props: {
        isOpen: true,
      },
    });

    await nextTick();
    expect(document.body.style.overflow).toBe('hidden');

    await wrapper.setProps({ isOpen: false });
    await nextTick();
    expect(document.body.style.overflow).toBe('');
  });
});
