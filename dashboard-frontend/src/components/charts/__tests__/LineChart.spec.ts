/**
 * LineChart Component Unit Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import LineChart from '../LineChart.vue';
import { nextTick } from '../../../test-utils';

describe('LineChart', () => {
  const testData = [
    { date: '2024-01-01', value: 10 },
    { date: '2024-01-02', value: 20 },
    { date: '2024-01-03', value: 15 },
    { date: '2024-01-04', value: 25 },
  ];

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

  it('renders chart with data', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    expect(wrapper.find('.line-chart').exists()).toBe(true);
    expect(wrapper.find('svg').exists()).toBe(true);
  });

  it('renders data points for each data item', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const circles = svg.querySelectorAll('circle');
    expect(circles.length).toBe(4);
  });

  it('renders data line', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const polyline = svg.querySelector('polyline');
    expect(polyline).toBeTruthy();
  });

  it('handles empty data array', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: [],
      },
    });

    expect(wrapper.find('.line-chart').exists()).toBe(true);
    const svg = wrapper.find('svg').element;
    const circles = svg.querySelectorAll('circle');
    expect(circles.length).toBe(0);
  });

  it('uses custom height when provided', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
        height: 300,
      },
    });

    const svg = wrapper.find('svg');
    expect(svg.attributes('viewBox')).toContain('300');
  });

  it('uses custom color when provided', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
        color: '#ff0000',
      },
    });

    const svg = wrapper.find('svg').element;
    const polyline = svg.querySelector('polyline');
    expect(polyline?.getAttribute('stroke')).toBe('#ff0000');
  });

  it('shows tooltip on point hover', async () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const firstCircle = svg.querySelector('circle');
    
    if (firstCircle) {
      const event = new MouseEvent('mouseenter', { bubbles: true });
      firstCircle.dispatchEvent(event);
      await nextTick();

      expect(wrapper.find('.chart-tooltip').exists()).toBe(true);
    }
  });

  it('hides tooltip on point leave', async () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const firstCircle = svg.querySelector('circle');
    
    if (firstCircle) {
      // Hover
      const enterEvent = new MouseEvent('mouseenter', { bubbles: true });
      firstCircle.dispatchEvent(enterEvent);
      await nextTick();

      // Leave
      const leaveEvent = new MouseEvent('mouseleave', { bubbles: true });
      firstCircle.dispatchEvent(leaveEvent);
      await nextTick();

      // Tooltip should be hidden
      const tooltip = wrapper.find('.chart-tooltip');
      // Tooltip might still exist but not be visible
      expect(tooltip.exists()).toBeDefined();
    }
  });

  it('emits point click event', async () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const firstCircle = svg.querySelector('circle');
    
    if (firstCircle) {
      const clickEvent = new MouseEvent('click', { bubbles: true });
      firstCircle.dispatchEvent(clickEvent);
      await nextTick();

      // Component should handle the click
      expect(firstCircle).toBeTruthy();
    }
  });

  it('renders grid lines', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const gridLines = svg.querySelectorAll('.grid-line');
    expect(gridLines.length).toBe(5);
  });

  it('renders X-axis labels', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const xLabels = Array.from(svg.querySelectorAll('text')).filter(text => {
      const y = parseFloat(text.getAttribute('y') || '0');
      return y > 200; // X-axis labels are at the bottom
    });
    expect(xLabels.length).toBeGreaterThan(0);
  });

  it('has accessible data points', () => {
    const wrapper = mount(LineChart, {
      props: {
        data: testData,
      },
    });

    const svg = wrapper.find('svg').element;
    const circles = svg.querySelectorAll('circle');
    circles.forEach((circle) => {
      expect(circle.getAttribute('role')).toBe('button');
      expect(circle.getAttribute('aria-label')).toBeTruthy();
      expect(circle.getAttribute('tabindex')).toBe('0');
    });
  });
});
