/**
 * TestResultsTable Component Unit Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import TestResultsTable from '../TestResultsTable.vue';

describe('TestResultsTable', () => {
  const testResults = [
    {
      testName: 'Test 1',
      testType: 'access-control',
      passed: true,
      timestamp: new Date('2024-01-01T10:00:00Z'),
    },
    {
      testName: 'Test 2',
      testType: 'network-policy',
      passed: false,
      timestamp: new Date('2024-01-01T11:00:00Z'),
    },
    {
      testName: 'Test 3',
      testType: 'dlp',
      passed: true,
      timestamp: new Date('2024-01-01T12:00:00Z'),
    },
  ];

  it('renders table with results', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    expect(wrapper.find('.table-container').exists()).toBe(true);
    expect(wrapper.find('table').exists()).toBe(true);
  });

  it('displays table title', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    expect(wrapper.text()).toContain('Recent Test Results');
  });

  it('renders table headers', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const headers = wrapper.findAll('th');
    expect(headers.length).toBe(4);
    expect(headers[0].text()).toBe('Test Name');
    expect(headers[1].text()).toBe('Type');
    expect(headers[2].text()).toBe('Status');
    expect(headers[3].text()).toBe('Timestamp');
  });

  it('renders test results in table rows', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(3);
  });

  it('displays test name in each row', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    expect(wrapper.text()).toContain('Test 1');
    expect(wrapper.text()).toContain('Test 2');
    expect(wrapper.text()).toContain('Test 3');
  });

  it('displays test type in each row', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    expect(wrapper.text()).toContain('access-control');
    expect(wrapper.text()).toContain('network-policy');
    expect(wrapper.text()).toContain('dlp');
  });

  it('displays PASSED status for passed tests', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const passedBadges = wrapper.findAll('.status-passed');
    expect(passedBadges.length).toBe(2); // Test 1 and Test 3
    passedBadges.forEach(badge => {
      expect(badge.text()).toBe('PASSED');
    });
  });

  it('displays FAILED status for failed tests', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const failedBadges = wrapper.findAll('.status-failed');
    expect(failedBadges.length).toBe(1); // Test 2
    expect(failedBadges[0].text()).toBe('FAILED');
  });

  it('displays formatted timestamps', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const timeElements = wrapper.findAll('time');
    expect(timeElements.length).toBe(3);
    timeElements.forEach((timeEl) => {
      expect(timeEl.attributes('datetime')).toBeTruthy();
    });
  });

  it('shows empty state when no results', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: [],
      },
    });

    expect(wrapper.find('.empty').exists()).toBe(true);
    expect(wrapper.text()).toContain('No test results available');
  });

  it('limits results to 10 items', () => {
    const manyResults = Array.from({ length: 15 }, (_, i) => ({
      testName: `Test ${i + 1}`,
      testType: 'access-control',
      passed: true,
      timestamp: new Date(),
    }));

    const wrapper = mount(TestResultsTable, {
      props: {
        results: manyResults,
      },
    });

    const rows = wrapper.findAll('tbody tr');
    expect(rows.length).toBe(10);
  });

  it('has correct ARIA attributes', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const heading = wrapper.find('#test-results-heading');
    expect(heading.exists()).toBe(true);

    const tableRegion = wrapper.find('[role="region"]');
    expect(tableRegion.exists()).toBe(true);
    expect(tableRegion.attributes('aria-labelledby')).toBe('test-results-heading');

    const caption = wrapper.find('caption');
    expect(caption.exists()).toBe(true);
    expect(caption.classes()).toContain('sr-only');
  });

  it('has accessible status badges', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: testResults,
      },
    });

    const statusBadges = wrapper.findAll('.status-badge');
    statusBadges.forEach((badge) => {
      expect(badge.attributes('aria-label')).toBeTruthy();
    });
  });

  it('has accessible empty state', () => {
    const wrapper = mount(TestResultsTable, {
      props: {
        results: [],
      },
    });

    const emptyState = wrapper.find('.empty');
    expect(emptyState.attributes('role')).toBe('status');
    expect(emptyState.attributes('aria-live')).toBe('polite');
  });
});
