/**
 * Dropdown Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mount } from '@vue/test-utils';
import Dropdown, { type DropdownOption } from '../Dropdown.vue';
import { nextTick } from '../../test-utils';

describe('Dropdown', () => {
  const options: DropdownOption[] = [
    { label: 'Option 1', value: 'opt1' },
    { label: 'Option 2', value: 'opt2' },
    { label: 'Option 3', value: 'opt3' },
  ];

  beforeEach(() => {
    // Mock document click listener
    document.addEventListener = vi.fn();
    document.removeEventListener = vi.fn();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('renders dropdown button', () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    expect(wrapper.find('.dropdown-button').exists()).toBe(true);
  });

  it('displays placeholder when no value selected', () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
        placeholder: 'Select an option',
      },
    });

    expect(wrapper.text()).toContain('Select an option');
  });

  it('displays selected option label', () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: 'opt2',
        options,
      },
    });

    expect(wrapper.text()).toContain('Option 2');
  });

  it('opens dropdown when button is clicked', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    const button = wrapper.find('.dropdown-button');
    await button.trigger('click');
    await nextTick();

    expect(wrapper.find('.dropdown-menu').exists()).toBe(true);
  });

  it('closes dropdown when button is clicked again', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    const button = wrapper.find('.dropdown-button');
    await button.trigger('click');
    await nextTick();

    await button.trigger('click');
    await nextTick();

    expect(wrapper.find('.dropdown-menu').exists()).toBe(false);
  });

  it('renders all options when opened', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const optionElements = wrapper.findAll('.dropdown-option');
    expect(optionElements.length).toBe(3);
  });

  it('emits update:modelValue when option is selected', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const firstOption = wrapper.findAll('.dropdown-option')[0];
    await firstOption.trigger('click');
    await nextTick();

    expect(wrapper.emitted('update:modelValue')).toBeTruthy();
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual(['opt1']);
  });

  it('emits change event when option is selected', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const firstOption = wrapper.findAll('.dropdown-option')[0];
    await firstOption.trigger('click');
    await nextTick();

    expect(wrapper.emitted('change')).toBeTruthy();
    expect(wrapper.emitted('change')?.[0]).toEqual(['opt1']);
  });

  it('highlights selected option', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: 'opt2',
        options,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const selectedOption = wrapper.findAll('.dropdown-option').find(opt => 
      opt.classes().includes('selected')
    );
    expect(selectedOption).toBeDefined();
  });

  it('disables option when disabled prop is true', async () => {
    const disabledOptions: DropdownOption[] = [
      { label: 'Option 1', value: 'opt1' },
      { label: 'Option 2', value: 'opt2', disabled: true },
      { label: 'Option 3', value: 'opt3' },
    ];

    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options: disabledOptions,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const disabledOption = wrapper.findAll('.dropdown-option').find(opt =>
      opt.classes().includes('disabled')
    );
    expect(disabledOption).toBeDefined();
  });

  it('handles grouped options', async () => {
    const groupedOptions = {
      'Group 1': [
        { label: 'Option 1', value: 'opt1' },
        { label: 'Option 2', value: 'opt2' },
      ],
      'Group 2': [
        { label: 'Option 3', value: 'opt3' },
      ],
    };

    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options: groupedOptions,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const groupLabels = wrapper.findAll('.group-label');
    expect(groupLabels.length).toBe(2);
    expect(groupLabels[0].text()).toBe('Group 1');
    expect(groupLabels[1].text()).toBe('Group 2');
  });

  it('shows empty state when no options available', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options: [],
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    expect(wrapper.find('.dropdown-empty').exists()).toBe(true);
    expect(wrapper.text()).toContain('No options available');
  });

  it('disables dropdown when disabled prop is true', () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
        disabled: true,
      },
    });

    const button = wrapper.find('.dropdown-button');
    expect(button.attributes('disabled')).toBeDefined();
  });

  it('has correct ARIA attributes', () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    const button = wrapper.find('.dropdown-button');
    expect(button.attributes('aria-expanded')).toBe('false');
    expect(button.attributes('aria-haspopup')).toBe('true');
  });

  it('updates ARIA expanded when opened', async () => {
    const wrapper = mount(Dropdown, {
      props: {
        modelValue: null,
        options,
      },
    });

    await wrapper.find('.dropdown-button').trigger('click');
    await nextTick();

    const button = wrapper.find('.dropdown-button');
    expect(button.attributes('aria-expanded')).toBe('true');
  });
});
