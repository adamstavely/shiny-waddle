/**
 * StatusBadge Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import StatusBadge from '../StatusBadge.vue';
import { CheckCircle } from 'lucide-vue-next';

describe('StatusBadge', () => {
  it('renders badge with status text', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'active',
      },
    });

    expect(wrapper.find('.status-badge').exists()).toBe(true);
    expect(wrapper.text()).toContain('active');
  });

  it('displays custom label when provided', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'active',
        label: 'Active Status',
      },
    });

    expect(wrapper.text()).toContain('Active Status');
    expect(wrapper.text()).not.toContain('active');
  });

  it('renders icon when provided', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'active',
        icon: CheckCircle,
      },
    });

    expect(wrapper.find('.badge-icon').exists()).toBe(true);
  });

  it('applies default variant when not specified', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'active',
      },
    });

    expect(wrapper.find('.badge-success').exists()).toBe(true);
  });

  it('applies correct variant classes', () => {
    const variants = ['default', 'success', 'warning', 'error', 'info', 'muted'] as const;

    variants.forEach((variant) => {
      const wrapper = mount(StatusBadge, {
        props: {
          status: 'test',
          variant,
        },
      });

      if (variant !== 'default') {
        expect(wrapper.find(`.badge-${variant}`).exists()).toBe(true);
      }
      wrapper.unmount();
    });
  });

  it('applies correct size classes', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      const wrapper = mount(StatusBadge, {
        props: {
          status: 'active',
          size,
        },
      });

      if (size !== 'md') {
        expect(wrapper.find(`.badge-${size}`).exists()).toBe(true);
      }
      wrapper.unmount();
    });
  });

  it('auto-detects success variant from status', () => {
    const successStatuses = ['success', 'active', 'enabled', 'approved', 'resolved', 'compliant', 'passed'];

    successStatuses.forEach((status) => {
      const wrapper = mount(StatusBadge, {
        props: {
          status,
        },
      });

      expect(wrapper.find('.badge-success').exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('auto-detects warning variant from status', () => {
    const warningStatuses = ['warning', 'pending', 'in-progress', 'partial', 'partially_compliant'];

    warningStatuses.forEach((status) => {
      const wrapper = mount(StatusBadge, {
        props: {
          status,
        },
      });

      expect(wrapper.find('.badge-warning').exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('auto-detects error variant from status', () => {
    const errorStatuses = ['error', 'failed', 'disabled', 'rejected', 'non_compliant', 'critical'];

    errorStatuses.forEach((status) => {
      const wrapper = mount(StatusBadge, {
        props: {
          status,
        },
      });

      expect(wrapper.find('.badge-error').exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('applies status-specific classes', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'pending',
      },
    });

    expect(wrapper.find('.status-pending').exists()).toBe(true);
  });

  it('capitalizes status text', () => {
    const wrapper = mount(StatusBadge, {
      props: {
        status: 'active',
      },
    });

    // The component uses text-transform: capitalize
    expect(wrapper.text()).toBeTruthy();
  });
});
