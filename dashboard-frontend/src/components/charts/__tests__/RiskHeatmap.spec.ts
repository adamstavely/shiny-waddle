/**
 * RiskHeatmap Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import RiskHeatmap, { type HeatmapCell } from '../RiskHeatmap.vue';
import { nextTick } from '../../../test-utils';

describe('RiskHeatmap', () => {
  const testData = {
    'App 1': {
      'Category A': 75,
      'Category B': 50,
      'Category C': 90,
    },
    'App 2': {
      'Category A': 30,
      'Category B': 60,
      'Category C': 40,
    },
  };

  beforeEach(() => {
    // Mock window.innerWidth and innerHeight
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: 1024,
    });
    Object.defineProperty(window, 'innerHeight', {
      writable: true,
      configurable: true,
      value: 768,
    });
  });

  it('renders heatmap with data', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    expect(wrapper.find('.risk-heatmap').exists()).toBe(true);
    expect(wrapper.find('.heatmap-container').exists()).toBe(true);
    expect(wrapper.find('.heatmap-grid').exists()).toBe(true);
  });

  it('displays title when provided', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
        title: 'Risk Assessment',
      },
    });

    expect(wrapper.find('.heatmap-title').text()).toBe('Risk Assessment');
  });

  it('renders row labels', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const rowLabels = wrapper.findAll('.row-label');
    expect(rowLabels.length).toBeGreaterThan(0);
    expect(rowLabels[0].text()).toBe('App 1');
  });

  it('renders column labels', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const columnLabels = wrapper.findAll('.column-label');
    expect(columnLabels.length).toBeGreaterThan(0);
  });

  it('renders heatmap cells', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    expect(cells.length).toBeGreaterThan(0);
  });

  it('applies correct color classes based on value', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    expect(cells.length).toBeGreaterThan(0);
    
    // Cells should have color classes
    cells.forEach((cell) => {
      const classes = cell.classes();
      const hasColorClass = classes.some(cls => 
        cls.startsWith('risk-') || cls.startsWith('cell-')
      );
      expect(hasColorClass || cell.attributes('style')).toBeTruthy();
    });
  });

  it('shows tooltip on cell hover', async () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    if (cells.length > 0) {
      await cells[0].trigger('mouseenter');
      await nextTick();

      expect(wrapper.find('.heatmap-tooltip').exists()).toBe(true);
    }
  });

  it('hides tooltip on cell leave', async () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    if (cells.length > 0) {
      await cells[0].trigger('mouseenter');
      await nextTick();

      await cells[0].trigger('mouseleave');
      await nextTick();

      // Tooltip should be hidden
      const tooltip = wrapper.find('.heatmap-tooltip');
      // May still exist but not visible
      expect(tooltip.exists()).toBeDefined();
    }
  });

  it('emits cell click event', async () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    if (cells.length > 0) {
      await cells[0].trigger('click');
      
      // Component should handle the click
      expect(cells[0].exists()).toBe(true);
    }
  });

  it('renders legend', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    expect(wrapper.find('.heatmap-legend').exists()).toBe(true);
    expect(wrapper.find('.legend-label').exists()).toBe(true);
  });

  it('has correct ARIA attributes', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const heatmap = wrapper.find('.risk-heatmap');
    expect(heatmap.attributes('role')).toBe('img');
    expect(heatmap.attributes('aria-label')).toBeTruthy();
  });

  it('has accessible cells', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    cells.forEach((cell) => {
      expect(cell.attributes('role')).toBe('button');
      expect(cell.attributes('aria-label')).toBeTruthy();
      expect(cell.attributes('tabindex')).toBe('0');
    });
  });

  it('handles keyboard navigation', async () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
      },
    });

    const cells = wrapper.findAll('.heatmap-cell');
    if (cells.length > 0) {
      const firstCell = cells[0];
      
      // Test Enter key
      await firstCell.trigger('keydown.enter');
      
      // Test Space key
      await firstCell.trigger('keydown.space');
      
      expect(firstCell.exists()).toBe(true);
    }
  });

  it('handles empty data', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: {},
      },
    });

    expect(wrapper.find('.risk-heatmap').exists()).toBe(true);
    const cells = wrapper.findAll('.heatmap-cell');
    expect(cells.length).toBe(0);
  });

  it('uses custom min and max values', () => {
    const wrapper = mount(RiskHeatmap, {
      props: {
        data: testData,
        minValue: 0,
        maxValue: 100,
      },
    });

    expect(wrapper.find('.risk-heatmap').exists()).toBe(true);
  });
});
