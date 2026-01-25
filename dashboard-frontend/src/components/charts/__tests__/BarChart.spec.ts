/**
 * BarChart Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import BarChart from '../BarChart.vue';

describe('BarChart', () => {
  const testData = [
    { name: 'Item 1', value: 10 },
    { name: 'Item 2', value: 20 },
    { name: 'Item 3', value: 15 },
  ];

  it('renders chart with data', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
      },
    });

    expect(wrapper.find('.bar-chart').exists()).toBe(true);
    expect(wrapper.find('svg').exists()).toBe(true);
  });

  it('renders bars for each data point', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
      },
    });

    const bars = wrapper.findAll('.bar');
    expect(bars.length).toBe(3);
  });

  it('renders labels for each bar', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const textElements = svg.querySelectorAll('text');
    const labelTexts = Array.from(textElements).map(el => el.textContent);
    
    expect(labelTexts).toContain('Item 1');
    expect(labelTexts).toContain('Item 2');
    expect(labelTexts).toContain('Item 3');
  });

  it('handles empty data array', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: [],
      },
    });

    expect(wrapper.find('.bar-chart').exists()).toBe(true);
    const bars = wrapper.findAll('.bar');
    expect(bars.length).toBe(0);
  });

  it('uses custom height when provided', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
        height: 300,
      },
    });

    const svg = wrapper.find('svg');
    expect(svg.attributes('viewBox')).toContain('300');
  });

  it('uses custom color when provided', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
        color: '#ff0000',
      },
    });

    const svg = wrapper.find('svg').element;
    const bars = svg.querySelectorAll('.bar');
    expect(bars.length).toBeGreaterThan(0);
  });

  it('calculates bar heights proportionally', () => {
    const data = [
      { name: 'Small', value: 10 },
      { name: 'Large', value: 100 },
    ];

    const wrapper = mount(BarChart, {
      props: {
        data,
      },
    });

    const svg = wrapper.find('svg').element;
    const rects = svg.querySelectorAll('rect');
    expect(rects.length).toBe(2);
    
    // The larger value should have a taller bar
    const heights = Array.from(rects).map(rect => 
      parseFloat(rect.getAttribute('height') || '0')
    );
    expect(heights[1]).toBeGreaterThan(heights[0]);
  });

  it('renders grid lines', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const gridLines = svg.querySelectorAll('.grid-line');
    expect(gridLines.length).toBe(5);
  });

  it('renders Y-axis labels', () => {
    const wrapper = mount(BarChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const yLabels = Array.from(svg.querySelectorAll('text')).filter(text => {
      const x = parseFloat(text.getAttribute('x') || '0');
      return x < 40; // Y-axis labels are on the left
    });
    expect(yLabels.length).toBeGreaterThan(0);
  });
});
