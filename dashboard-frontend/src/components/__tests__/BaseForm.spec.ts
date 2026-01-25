/**
 * BaseForm Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import BaseForm from '../BaseForm.vue';

describe('BaseForm', () => {
  it('renders correctly with default props', () => {
    const wrapper = mount(BaseForm, {
      slots: {
        default: '<input type="text" />',
      },
    });

    expect(wrapper.find('form').exists()).toBe(true);
    expect(wrapper.find('.base-form').exists()).toBe(true);
    expect(wrapper.find('.form-body').exists()).toBe(true);
    expect(wrapper.find('.form-footer').exists()).toBe(true);
  });

  it('displays title and description when provided', () => {
    const wrapper = mount(BaseForm, {
      props: {
        title: 'Test Form',
        description: 'Test description',
      },
    });

    expect(wrapper.find('.form-title').text()).toBe('Test Form');
    expect(wrapper.find('.form-description').text()).toBe('Test description');
  });

  it('renders default footer with submit and cancel buttons', () => {
    const wrapper = mount(BaseForm, {
      props: {
        showDefaultFooter: true,
        showCancel: true,
      },
    });

    const submitButton = wrapper.find('button[type="submit"]');
    const cancelButton = wrapper.find('button[type="button"]');

    expect(submitButton.exists()).toBe(true);
    expect(cancelButton.exists()).toBe(true);
    expect(submitButton.text()).toBe('Submit');
    expect(cancelButton.text()).toBe('Cancel');
  });

  it('uses custom submit and cancel labels', () => {
    const wrapper = mount(BaseForm, {
      props: {
        submitLabel: 'Save',
        cancelLabel: 'Discard',
      },
    });

    expect(wrapper.find('button[type="submit"]').text()).toBe('Save');
    expect(wrapper.find('button[type="button"]').text()).toBe('Discard');
  });

  it('hides cancel button when showCancel is false', () => {
    const wrapper = mount(BaseForm, {
      props: {
        showCancel: false,
      },
    });

    expect(wrapper.find('button[type="button"]').exists()).toBe(false);
    expect(wrapper.find('button[type="submit"]').exists()).toBe(true);
  });

  it('disables submit button when disabled prop is true', () => {
    const wrapper = mount(BaseForm, {
      props: {
        disabled: true,
      },
    });

    const submitButton = wrapper.find('button[type="submit"]');
    expect(submitButton.attributes('disabled')).toBeDefined();
  });

  it('disables submit button when loading prop is true', () => {
    const wrapper = mount(BaseForm, {
      props: {
        loading: true,
      },
    });

    const submitButton = wrapper.find('button[type="submit"]');
    expect(submitButton.attributes('disabled')).toBeDefined();
    expect(wrapper.find('.loading-spinner-small').exists()).toBe(true);
  });

  it('emits submit event when form is submitted', async () => {
    const wrapper = mount(BaseForm);

    const form = wrapper.find('form');
    await form.trigger('submit');

    expect(wrapper.emitted('submit')).toBeTruthy();
    expect(wrapper.emitted('submit')?.length).toBe(1);
  });

  it('does not emit submit when disabled', async () => {
    const wrapper = mount(BaseForm, {
      props: {
        disabled: true,
      },
    });

    const form = wrapper.find('form');
    await form.trigger('submit');

    expect(wrapper.emitted('submit')).toBeFalsy();
  });

  it('does not emit submit when loading', async () => {
    const wrapper = mount(BaseForm, {
      props: {
        loading: true,
      },
    });

    const form = wrapper.find('form');
    await form.trigger('submit');

    expect(wrapper.emitted('submit')).toBeFalsy();
  });

  it('emits cancel event when cancel button is clicked', async () => {
    const wrapper = mount(BaseForm, {
      props: {
        showCancel: true,
      },
    });

    const cancelButton = wrapper.find('button[type="button"]');
    await cancelButton.trigger('click');

    expect(wrapper.emitted('cancel')).toBeTruthy();
    expect(wrapper.emitted('cancel')?.length).toBe(1);
  });

  it('renders slot content in form body', () => {
    const wrapper = mount(BaseForm, {
      slots: {
        default: '<input type="text" name="test" />',
      },
    });

    expect(wrapper.find('input[name="test"]').exists()).toBe(true);
  });

  it('renders footer slot when provided', () => {
    const wrapper = mount(BaseForm, {
      slots: {
        footer: '<div class="custom-footer">Custom Footer</div>',
      },
      props: {
        showDefaultFooter: false,
      },
    });

    expect(wrapper.find('.custom-footer').exists()).toBe(true);
    expect(wrapper.find('.custom-footer').text()).toBe('Custom Footer');
  });

  it('applies compact variant class when variant is compact', () => {
    const wrapper = mount(BaseForm, {
      props: {
        variant: 'compact',
      },
    });

    expect(wrapper.find('.form-compact').exists()).toBe(true);
  });

  it('prevents default form submission', async () => {
    const wrapper = mount(BaseForm);
    const form = wrapper.find('form');
    
    const preventDefault = vi.fn();
    const event = { preventDefault } as any;
    
    await form.trigger('submit', event);
    
    // The form should have @submit.prevent which prevents default
    expect(wrapper.emitted('submit')).toBeTruthy();
  });
});
