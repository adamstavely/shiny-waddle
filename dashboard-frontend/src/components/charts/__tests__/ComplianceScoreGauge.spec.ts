/**
 * ComplianceScoreGauge Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import ComplianceScoreGauge from '../ComplianceScoreGauge.vue';

describe('ComplianceScoreGauge', () => {
  it('renders gauge with score', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
      },
    });

    expect(wrapper.find('.compliance-score-gauge').exists()).toBe(true);
    expect(wrapper.find('svg').exists()).toBe(true);
  });

  it('displays score percentage', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85.5,
      },
    });

    const svg = wrapper.find('svg').element;
    const textElements = Array.from(svg.querySelectorAll('text'));
    const scoreText = textElements.find(text => text.classList.contains('score-text'));
    expect(scoreText?.textContent).toContain('85.5%');
  });

  it('uses green color for high scores (>=90)', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 95,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreArc = svg.querySelector('.score-arc');
    expect(scoreArc?.getAttribute('stroke')).toBe('#48bb78');
  });

  it('uses blue color for medium-high scores (70-89)', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 80,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreArc = svg.querySelector('.score-arc');
    expect(scoreArc?.getAttribute('stroke')).toBe('#4facfe');
  });

  it('uses orange color for medium scores (50-69)', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 60,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreArc = svg.querySelector('.score-arc');
    expect(scoreArc?.getAttribute('stroke')).toBe('#ed8936');
  });

  it('uses red color for low scores (<50)', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 40,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreArc = svg.querySelector('.score-arc');
    expect(scoreArc?.getAttribute('stroke')).toBe('#fc8181');
  });

  it('renders trend icon when trend is provided', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
        trend: 'improving',
      },
    });

    expect(wrapper.find('.trend-icon').exists()).toBe(true);
    expect(wrapper.find('.trend-improving').exists()).toBe(true);
  });

  it('renders improving trend icon', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
        trend: 'improving',
      },
    });

    expect(wrapper.find('.trend-improving').exists()).toBe(true);
  });

  it('renders declining trend icon', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
        trend: 'declining',
      },
    });

    expect(wrapper.find('.trend-declining').exists()).toBe(true);
  });

  it('renders stable trend icon', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
        trend: 'stable',
      },
    });

    expect(wrapper.find('.trend-stable').exists()).toBe(true);
  });

  it('renders background arc', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
      },
    });

    const svg = wrapper.find('svg').element;
    const backgroundArc = svg.querySelector('.background-arc');
    expect(backgroundArc).toBeTruthy();
  });

  it('renders score arc', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 85,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreArc = svg.querySelector('.score-arc');
    expect(scoreArc).toBeTruthy();
  });

  it('calculates arc length based on score', () => {
    const highScoreWrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 90,
      },
    });

    const lowScoreWrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 30,
      },
    });

    const highSvg = highScoreWrapper.find('svg').element;
    const lowSvg = lowScoreWrapper.find('svg').element;
    
    const highArc = highSvg.querySelector('.score-arc');
    const lowArc = lowSvg.querySelector('.score-arc');
    
    // Both should exist
    expect(highArc).toBeTruthy();
    expect(lowArc).toBeTruthy();
    
    // The arc paths should be different
    expect(highArc?.getAttribute('d')).not.toBe(lowArc?.getAttribute('d'));
  });

  it('handles score of 0', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 0,
      },
    });

    expect(wrapper.find('.compliance-score-gauge').exists()).toBe(true);
    const svg = wrapper.find('svg').element;
    const scoreText = Array.from(svg.querySelectorAll('text')).find(
      text => text.classList.contains('score-text')
    );
    expect(scoreText?.textContent).toContain('0.0%');
  });

  it('handles score of 100', () => {
    const wrapper = mount(ComplianceScoreGauge, {
      props: {
        score: 100,
      },
    });

    const svg = wrapper.find('svg').element;
    const scoreText = Array.from(svg.querySelectorAll('text')).find(
      text => text.classList.contains('score-text')
    );
    expect(scoreText?.textContent).toContain('100.0%');
  });
});
