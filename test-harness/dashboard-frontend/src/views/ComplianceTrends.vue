<template>
  <div class="compliance-trends-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Compliance Trends</h1>
          <p class="page-description">Track compliance metrics and trends over time</p>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-section">
      <div class="filter-group">
        <label>Application</label>
        <select v-model="filters.applicationId">
          <option value="">All Applications</option>
          <option v-for="app in applications" :key="app.id" :value="app.id">
            {{ app.name }}
          </option>
        </select>
      </div>
      <div class="filter-group">
        <label>Time Period</label>
        <select v-model="filters.period">
          <option value="day">Daily</option>
          <option value="week">Weekly</option>
          <option value="month">Monthly</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Date Range</label>
        <div class="date-range-inputs">
          <input
            v-model="filters.startDate"
            type="date"
          />
          <span>to</span>
          <input
            v-model="filters.endDate"
            type="date"
          />
        </div>
      </div>
    </div>

    <!-- Loading/Error States -->
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading compliance metrics...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <button @click="reload" class="btn-retry">Retry</button>
    </div>

    <!-- Metrics Display -->
    <div v-else-if="metrics" class="metrics-section">
      <!-- Overall Metrics Cards -->
      <div class="metrics-cards">
        <div class="metric-card gauge-card">
          <div class="metric-label">Compliance Score</div>
          <ComplianceScoreGauge
            :score="metrics.overall.passRate"
            :trend="metrics.overall.trend"
          />
        </div>
        <div class="metric-card">
          <div class="metric-label">Overall Pass Rate</div>
          <div class="metric-value-large" :class="getPassRateClass(metrics.overall.passRate)">
            {{ metrics.overall.passRate.toFixed(1) }}%
          </div>
          <div class="metric-trend" :class="`trend-${metrics.overall.trend}`">
            <component :is="getTrendIcon(metrics.overall.trend)" class="trend-icon" />
            {{ metrics.overall.trend }}
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Total Tests</div>
          <div class="metric-value">{{ metrics.overall.totalTests }}</div>
          <div class="metric-detail">
            <span class="detail-passed">{{ metrics.overall.passed }} passed</span>
            <span class="detail-failed">{{ metrics.overall.failed }} failed</span>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Average Duration</div>
          <div class="metric-value">{{ formatDuration(metrics.overall.averageDuration) }}</div>
        </div>
      </div>

      <!-- Pass Rate Trend Chart -->
      <div class="chart-section">
        <h3 class="section-title">Pass Rate Trend</h3>
        <div class="chart-container">
          <PassRateTrendChart :data="metrics.trends" />
        </div>
      </div>

      <!-- Test Execution Volume Chart -->
      <div class="chart-section">
        <h3 class="section-title">Test Execution Volume</h3>
        <div class="chart-container">
          <TestExecutionVolumeChart :data="metrics.trends" :period="filters.period" />
        </div>
      </div>

      <!-- Status Breakdown -->
      <div class="chart-section">
        <h3 class="section-title">Status Breakdown</h3>
        <div class="chart-container">
          <TestStatusBreakdown :metrics="metrics.overall" />
        </div>
      </div>

      <!-- By Test Configuration -->
      <div v-if="Object.keys(metrics.byTestConfiguration).length > 0" class="config-metrics-section">
        <h3 class="section-title">By Test Configuration</h3>
        <div class="config-metrics-grid">
          <div
            v-for="(configMetrics, configId) in metrics.byTestConfiguration"
            :key="configId"
            class="config-metric-card"
          >
            <div class="config-name">{{ configMetrics.configName }}</div>
            <div class="config-type">{{ configMetrics.configType }}</div>
            <div class="config-pass-rate" :class="getPassRateClass(configMetrics.passRate)">
              {{ configMetrics.passRate.toFixed(1) }}%
            </div>
            <div class="config-stats">
              {{ configMetrics.passed }}/{{ configMetrics.totalTests }} passed
            </div>
          </div>
        </div>
      </div>

      <!-- Failing Tests -->
      <div v-if="metrics.failingTests.length > 0" class="failing-tests-section">
        <h3 class="section-title">Failing Tests</h3>
        <div class="failing-tests-list">
          <div
            v-for="failing in metrics.failingTests"
            :key="failing.configId"
            class="failing-test-item"
          >
            <div class="failing-test-info">
              <div class="failing-test-name">{{ failing.configName }}</div>
              <div class="failing-test-details">
                {{ failing.failureCount }} failure{{ failing.failureCount !== 1 ? 's' : '' }} • 
                Last: {{ formatDateTime(failing.lastFailure) }}
              </div>
            </div>
            <button @click="viewTestHistory(failing.configId)" class="btn-secondary">
              View History
            </button>
          </div>
        </div>
      </div>

      <!-- Recent Test Executions -->
      <div v-if="recentExecutions.length > 0" class="recent-executions-section">
        <h3 class="section-title">Recent Test Executions</h3>
        <div class="recent-executions-table">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Application</th>
                <th>Test Configuration</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="execution in recentExecutions"
                :key="execution.id"
                class="execution-row"
              >
                <td>{{ formatDateTime(execution.timestamp) }}</td>
                <td>{{ execution.applicationName }}</td>
                <td>{{ execution.testConfigurationName }}</td>
                <td>
                  <span class="status-badge" :class="`status-${execution.status}`">
                    {{ execution.status }}
                  </span>
                </td>
                <td>
                  <span v-if="execution.duration">{{ formatDuration(execution.duration) }}</span>
                  <span v-else class="text-muted">-</span>
                </td>
                <td>
                  <button @click="viewExecutionResult(execution)" class="btn-icon" title="View Details">
                    <Eye class="icon" />
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div v-else class="empty-state">
      <TrendingUp class="empty-icon" />
      <p>No compliance data available</p>
      <p class="empty-subtitle">Compliance metrics will appear here after tests are executed</p>
    </div>

    <!-- Test Result Modal -->
    <TestResultModal
      v-model:isOpen="showResultModal"
      :result="selectedResult"
      @close="showResultModal = false; selectedResult = null"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { useRouter } from 'vue-router';
import { TrendingUp, TrendingDown, Minus, ArrowUp, ArrowDown, Eye } from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import PassRateTrendChart from '../components/charts/PassRateTrendChart.vue';
import TestStatusBreakdown from '../components/charts/TestStatusBreakdown.vue';
import ComplianceScoreGauge from '../components/charts/ComplianceScoreGauge.vue';
import TestExecutionVolumeChart from '../components/charts/TestExecutionVolumeChart.vue';
import TestResultModal from '../components/TestResultModal.vue';
import type { ComplianceMetrics } from '../types/test-results';
import { useApiDataAuto } from '../composables/useApiData';
import { useModal } from '../composables/useModal';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Compliance', to: '/compliance' },
  { label: 'Compliance Trends' },
];

const applications = ref<any[]>([]);
const recentExecutions = ref<any[]>([]);

const filters = ref({
  applicationId: '',
  period: 'day' as 'day' | 'week' | 'month',
  startDate: '',
  endDate: '',
});

// Use composable for API data fetching
const { data: metrics, loading, error, reload } = useApiDataAuto(
  async () => {
    const params: any = {};
    if (filters.value.applicationId) {
      params.applicationId = filters.value.applicationId;
    }
    if (filters.value.startDate) {
      params.startDate = filters.value.startDate;
    }
    if (filters.value.endDate) {
      params.endDate = filters.value.endDate;
    }

    const response = await axios.get('/api/test-results/compliance/metrics', { params });
    return {
      ...response.data,
      period: {
        start: new Date(response.data.period.start),
        end: new Date(response.data.period.end),
      },
      failingTests: response.data.failingTests.map((ft: any) => ({
        ...ft,
        lastFailure: new Date(ft.lastFailure),
      })),
    };
  },
  {
    initialData: null,
    errorMessage: 'Failed to load compliance metrics',
  }
);

// Use composable for modal state
const resultModal = useModal<any>();

// Watch filters and reload metrics
watch(() => filters.value, () => {
  reload();
}, { deep: true });

const loadApplications = async () => {
  try {
    const response = await axios.get("/api/v1/applications");
    applications.value = response.data;
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};


const getPassRateClass = (passRate: number) => {
  if (passRate >= 90) return 'pass-rate-excellent';
  if (passRate >= 70) return 'pass-rate-good';
  if (passRate >= 50) return 'pass-rate-warning';
  return 'pass-rate-poor';
};

const getTrendIcon = (trend: string) => {
  if (trend === 'improving') return ArrowUp;
  if (trend === 'declining') return ArrowDown;
  return Minus;
};

const formatDuration = (ms: number) => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
};

const formatDateTime = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const viewTestHistory = (applicationId: string) => {
  router.push(`/test-history?applicationId=${applicationId}`);
};

const loadRecentExecutions = async () => {
  try {
    const params: any = { limit: 10 };
    if (filters.value.applicationId) {
      params.applicationId = filters.value.applicationId;
    }
    const response = await axios.get('/api/test-results', { params });
    recentExecutions.value = response.data.map((r: any) => ({
      ...r,
      timestamp: new Date(r.timestamp),
      createdAt: new Date(r.createdAt),
    }));
  } catch (err: any) {
    console.error('Error loading recent executions:', err);
    recentExecutions.value = [];
  }
};

const viewExecutionResult = (result: any) => {
  resultModal.open(result);
};

onMounted(async () => {
  // Set default date range to last 30 days
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 30);
  
  filters.value.endDate = endDate.toISOString().split('T')[0];
  filters.value.startDate = startDate.toISOString().split('T')[0];
  
  await Promise.all([loadApplications(), loadMetrics(), loadRecentExecutions()]);
});
</script>

<style scoped>
.compliance-trends-page {
  width: 100%;
  max-width: 1600px;
  margin: 0 auto;
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.filters-section {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-base);
  margin-bottom: var(--spacing-xl);
  padding: var(--spacing-lg);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  min-width: 150px;
}

.filter-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
}

.filter-group select,
.filter-group input {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  opacity: 0.05;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.date-range-inputs {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.date-range-inputs input {
  flex: 1;
}

.date-range-inputs span {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.loading-state,
.error-state {
  padding: var(--spacing-xl);
  text-align: center;
}

.loading {
  color: var(--color-primary);
  font-size: var(--font-size-lg);
}

.error {
  color: var(--color-error);
  font-size: var(--font-size-lg);
  margin-bottom: var(--spacing-base);
}

.btn-retry {
  padding: var(--spacing-md) var(--spacing-lg);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  cursor: pointer;
  font-weight: var(--font-weight-medium);
}

.metrics-section {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.metrics-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
}

.gauge-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.metric-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.metric-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.metric-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.metric-value-large {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  margin: var(--spacing-xs) 0;
}

.pass-rate-excellent {
  color: var(--color-success);
}

.pass-rate-good {
  color: var(--color-primary);
}

.pass-rate-warning {
  color: var(--color-warning);
}

.pass-rate-poor {
  color: var(--color-error);
}

.metric-trend {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-xs);
}

.trend-improving {
  color: var(--color-success);
}

.trend-declining {
  color: var(--color-error);
}

.trend-stable {
  color: var(--color-text-secondary);
}

.trend-icon {
  width: 1rem;
  height: 1rem;
}

.metric-detail {
  display: flex;
  gap: var(--spacing-base);
  margin-top: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.detail-passed {
  color: var(--color-success);
}

.detail-failed {
  color: var(--color-error);
}

.chart-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.chart-container {
  min-height: 300px;
}

.config-metrics-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.config-metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: var(--spacing-base);
}

.config-metric-card {
  background: var(--color-bg-overlay-dark);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-base);
}

.config-name {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.config-type {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin-bottom: var(--spacing-xs);
}

.config-pass-rate {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  margin: var(--spacing-xs) 0;
}

.config-stats {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.failing-tests-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.failing-tests-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-base);
}

.failing-test-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-base);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
}

.failing-test-name {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.failing-test-details {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.empty-state {
  padding: var(--spacing-xl) var(--spacing-xl);
  text-align: center;
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto var(--spacing-base);
  opacity: 0.5;
  color: var(--color-text-muted);
}

.empty-subtitle {
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-xs);
}

.btn-secondary {
  padding: var(--spacing-xs) var(--spacing-base);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  cursor: pointer;
  font-weight: var(--font-weight-medium);
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: var(--border-color-primary);
  opacity: 0.2;
}

.recent-executions-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  padding: 1.5rem;
}

.recent-executions-table {
  overflow-x: auto;
}

.recent-executions-table table {
  width: 100%;
  border-collapse: collapse;
}

.recent-executions-table thead {
  background: var(--border-color-muted);
}

.recent-executions-table th {
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
}

.recent-executions-table td {
  padding: 1rem;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.execution-row:hover {
  background: var(--border-color-muted);
  opacity: 0.5;
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: capitalize;
}

.status-badge.status-passed {
  background: var(--color-success-bg);
  color: var(--color-success);
  border: var(--border-width-thin) solid var(--color-success);
  opacity: 0.3;
}

.status-badge.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
}

.status-badge.status-partial {
  background: var(--color-warning-bg);
  color: var(--color-warning);
  border: var(--border-width-thin) solid var(--color-warning);
  opacity: 0.3;
}

.status-badge.status-error {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
}

.text-muted {
  color: var(--color-text-muted);
  font-style: italic;
}

.btn-icon {
  padding: 0.5rem;
  background: transparent;
  border: none;
  cursor: pointer;
  border-radius: var(--border-radius-sm);
  color: var(--color-text-secondary);
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.btn-icon:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
}
</style>

