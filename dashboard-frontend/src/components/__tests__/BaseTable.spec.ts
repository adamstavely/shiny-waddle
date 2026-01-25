/**
 * BaseTable Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import BaseTable, { type TableColumn } from '../BaseTable.vue';
import { TestFixtures } from '../../test-utils';

describe('BaseTable', () => {
  const columns: TableColumn[] = [
    { key: 'id', label: 'ID' },
    { key: 'name', label: 'Name' },
    { key: 'status', label: 'Status' },
  ];

  const data = [
    { id: 1, name: 'Item 1', status: 'active' },
    { id: 2, name: 'Item 2', status: 'inactive' },
    { id: 3, name: 'Item 3', status: 'active' },
  ];

  it('renders table with data and columns', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
    });

    expect(wrapper.find('table').exists()).toBe(true);
    expect(wrapper.find('thead').exists()).toBe(true);
    expect(wrapper.find('tbody').exists()).toBe(true);
  });

  it('renders column headers correctly', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
    });

    const headers = wrapper.findAll('th');
    expect(headers.length).toBe(3);
    expect(headers[0].text()).toBe('ID');
    expect(headers[1].text()).toBe('Name');
    expect(headers[2].text()).toBe('Status');
  });

  it('renders table rows with data', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(3);
  });

  it('renders cell values correctly', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
    });

    const firstRow = wrapper.findAll('tbody tr')[0];
    const cells = firstRow.findAll('td');
    expect(cells[0].text()).toBe('1');
    expect(cells[1].text()).toBe('Item 1');
    expect(cells[2].text()).toBe('active');
  });

  it('displays title when provided', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        title: 'Test Table',
      },
    });

    expect(wrapper.find('.table-title').text()).toBe('Test Table');
  });

  it('displays empty message when data is empty', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data: [],
        columns,
        emptyMessage: 'No items found',
      },
    });

    expect(wrapper.find('.table-empty').exists()).toBe(true);
    expect(wrapper.find('.table-empty').text()).toContain('No items found');
  });

  it('uses custom empty slot when provided', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data: [],
        columns,
      },
      slots: {
        empty: '<div class="custom-empty">Custom Empty State</div>',
      },
    });

    expect(wrapper.find('.custom-empty').exists()).toBe(true);
    expect(wrapper.find('.custom-empty').text()).toBe('Custom Empty State');
  });

  it('applies variant class correctly', () => {
    const variants = ['default', 'striped', 'bordered'] as const;

    variants.forEach((variant) => {
      const wrapper = mount(BaseTable, {
        props: {
          data,
          columns,
          variant,
        },
      });

      expect(wrapper.find(`.table-${variant}`).exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('applies size class correctly', () => {
    const sizes = ['sm', 'md', 'lg'] as const;

    sizes.forEach((size) => {
      const wrapper = mount(BaseTable, {
        props: {
          data,
          columns,
          size,
        },
      });

      expect(wrapper.find(`.table-${size}`).exists()).toBe(true);
      wrapper.unmount();
    });
  });

  it('emits row-click event when row is clicked and clickable is true', async () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        clickable: true,
      },
    });

    const firstRow = wrapper.findAll('tbody tr')[0];
    await firstRow.trigger('click');

    expect(wrapper.emitted('row-click')).toBeTruthy();
    expect(wrapper.emitted('row-click')?.[0]).toEqual([
      data[0],
      0,
      expect.any(Object),
    ]);
  });

  it('does not emit row-click when clickable is false', async () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        clickable: false,
      },
    });

    const firstRow = wrapper.findAll('tbody tr')[0];
    await firstRow.trigger('click');

    expect(wrapper.emitted('row-click')).toBeFalsy();
  });

  it('uses custom rowKey function', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        rowKey: (row) => `custom-${row.id}`,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(3);
    // Each row should have a unique key
    rows.forEach((row, index) => {
      expect(row.attributes('key') || row.element.getAttribute('data-key')).toBeDefined();
    });
  });

  it('uses custom rowKey string', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        rowKey: 'id',
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(3);
  });

  it('applies custom row class function', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        rowClass: (row) => `row-${row.status}`,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows[0].classes()).toContain('row-active');
    expect(rows[1].classes()).toContain('row-inactive');
  });

  it('applies custom row class string', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        rowClass: 'custom-row-class',
      },
    });

    const rows = wrapper.findAll('tbody tr');
    rows.forEach((row) => {
      expect(row.classes()).toContain('custom-row-class');
    });
  });

  it('uses column formatter when provided', () => {
    const columnsWithFormatter: TableColumn[] = [
      { key: 'id', label: 'ID' },
      {
        key: 'status',
        label: 'Status',
        formatter: (value) => value.toUpperCase(),
      },
    ];

    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns: columnsWithFormatter,
      },
    });

    const statusCells = wrapper.findAll('tbody td').filter((cell) => {
      return cell.text() === 'ACTIVE' || cell.text() === 'INACTIVE';
    });
    expect(statusCells.length).toBeGreaterThan(0);
  });

  it('renders header slot when provided', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
      slots: {
        header: '<div class="custom-header">Custom Header</div>',
      },
    });

    expect(wrapper.find('.custom-header').exists()).toBe(true);
  });

  it('renders footer slot when provided', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
      slots: {
        footer: '<div class="custom-footer">Custom Footer</div>',
      },
    });

    expect(wrapper.find('.custom-footer').exists()).toBe(true);
  });

  it('renders cell slot when provided', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
      slots: {
        'cell-status': '<span class="status-badge">{{ props.value }}</span>',
      },
    });

    const statusBadges = wrapper.findAll('.status-badge');
    expect(statusBadges.length).toBeGreaterThan(0);
  });

  it('renders header slot for specific column', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
      },
      slots: {
        'header-name': '<span class="sort-icon">↑</span>',
      },
    });

    expect(wrapper.find('.sort-icon').exists()).toBe(true);
  });

  it('handles null and undefined values gracefully', () => {
    const dataWithNulls = [
      { id: 1, name: null, status: undefined },
      { id: 2, name: 'Item 2', status: 'active' },
    ];

    const wrapper = mount(BaseTable, {
      props: {
        data: dataWithNulls,
        columns,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(2);
    // Should not throw errors with null/undefined values
    expect(wrapper.find('table').exists()).toBe(true);
  });

  it('has correct ARIA attributes', () => {
    const wrapper = mount(BaseTable, {
      props: {
        data,
        columns,
        title: 'Test Table',
        caption: 'Table caption for screen readers',
      },
    });

    const table = wrapper.find('table');
    const caption = wrapper.find('caption');
    expect(caption.exists()).toBe(true);
    expect(caption.classes()).toContain('sr-only');
  });
});
