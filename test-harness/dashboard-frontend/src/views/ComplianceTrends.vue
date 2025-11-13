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
        <select v-model="filters.applicationId" @change="loadMetrics">
          <option value="">All Applications</option>
          <option v-for="app in applications" :key="app.id" :value="app.id">
            {{ app.name }}
          </option>
        </select>
      </div>
      <div class="filter-group">
        <label>Test Configuration</label>
        <select v-model="filters.testConfigurationId" @change="loadMetrics">
          <option value="">All Configurations</option>
          <option v-for="config in testConfigurations" :key="config.id" :value="config.id">
            {{ config.name }}
          </option>
        </select>
      </div>
      <div class="filter-group">
        <label>Time Period</label>
        <select v-model="filters.period" @change="loadMetrics">
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
            @change="loadMetrics"
          />
          <span>to</span>
          <input
            v-model="filters.endDate"
            type="date"
            @change="loadMetrics"
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
      <button @click="loadMetrics" class="btn-retry">Retry</button>
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
import { ref, onMounted } from 'vue';
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

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Compliance', to: '/compliance' },
  { label: 'Compliance Trends' },
];

const loading = ref(false);
const error = ref<string | null>(null);
const metrics = ref<ComplianceMetrics | null>(null);
const applications = ref<any[]>([]);
const testConfigurations = ref<any[]>([]);
const recentExecutions = ref<any[]>([]);
const showResultModal = ref(false);
const selectedResult = ref<any>(null);

const filters = ref({
  applicationId: '',
  testConfigurationId: '',
  period: 'day' as 'day' | 'week' | 'month',
  startDate: '',
  endDate: '',
});

const loadMetrics = async () => {
  loading.value = true;
  error.value = null;
  try {
    const params: any = {};
    if (filters.value.applicationId) {
      params.applicationId = filters.value.applicationId;
    }
    if (filters.value.testConfigurationId) {
      params.testConfigurationId = filters.value.testConfigurationId;
    }
    if (filters.value.startDate) {
      params.startDate = filters.value.startDate;
    }
    if (filters.value.endDate) {
      params.endDate = filters.value.endDate;
    }

    const response = await axios.get('/api/test-results/compliance/metrics', { params });
    metrics.value = {
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
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load compliance metrics';
    console.error('Error loading compliance metrics:', err);
  } finally {
    loading.value = false;
  }
};

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/applications');
    applications.value = response.data;
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};

const loadTestConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations');
    testConfigurations.value = response.data;
  } catch (err) {
    console.error('Error loading test configurations:', err);
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

const viewTestHistory = (configId: string) => {
  router.push(`/test-history?testConfigurationId=${configId}`);
};

const loadRecentExecutions = async () => {
  try {
    const params: any = { limit: 10 };
    if (filters.value.applicationId) {
      params.applicationId = filters.value.applicationId;
    }
    if (filters.value.testConfigurationId) {
      params.testConfigurationId = filters.value.testConfigurationId;
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
  selectedResult.value = result;
  showResultModal.value = true;
};

onMounted(async () => {
  // Set default date range to last 30 days
  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - 30);
  
  filters.value.endDate = endDate.toISOString().split('T')[0];
  filters.value.startDate = startDate.toISOString().split('T')[0];
  
  await Promise.all([loadApplications(), loadTestConfigurations(), loadMetrics(), loadRecentExecutions()]);
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
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.filters-section {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  margin-bottom: 2rem;
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-width: 150px;
}

.filter-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.filter-group select,
.filter-group input {
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
}

.date-range-inputs {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.date-range-inputs input {
  flex: 1;
}

.date-range-inputs span {
  color: #a0aec0;
  font-size: 0.875rem;
}

.loading-state,
.error-state {
  padding: 3rem;
  text-align: center;
}

.loading {
  color: #4facfe;
  font-size: 1.1rem;
}

.error {
  color: #fc8181;
  font-size: 1.1rem;
  margin-bottom: 1rem;
}

.btn-retry {
  padding: 0.75rem 1.5rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 0.5rem;
}

.metric-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
}

.metric-value-large {
  font-size: 3rem;
  font-weight: 700;
  margin: 0.5rem 0;
}

.pass-rate-excellent {
  color: #48bb78;
}

.pass-rate-good {
  color: #4facfe;
}

.pass-rate-warning {
  color: #ed8936;
}

.pass-rate-poor {
  color: #fc8181;
}

.metric-trend {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.trend-improving {
  color: #48bb78;
}

.trend-declining {
  color: #fc8181;
}

.trend-stable {
  color: #a0aec0;
}

.trend-icon {
  width: 1rem;
  height: 1rem;
}

.metric-detail {
  display: flex;
  gap: 1rem;
  margin-top: 0.5rem;
  font-size: 0.875rem;
}

.detail-passed {
  color: #48bb78;
}

.detail-failed {
  color: #fc8181;
}

.chart-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 1.5rem;
}

.chart-container {
  min-height: 300px;
}

.config-metrics-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.config-metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 1rem;
}

.config-metric-card {
  background: rgba(15, 20, 25, 0.8);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
}

.config-name {
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.25rem;
}

.config-type {
  font-size: 0.75rem;
  color: #718096;
  margin-bottom: 0.5rem;
}

.config-pass-rate {
  font-size: 1.5rem;
  font-weight: 700;
  margin: 0.5rem 0;
}

.config-stats {
  font-size: 0.875rem;
  color: #a0aec0;
}

.failing-tests-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(252, 129, 129, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.failing-tests-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.failing-test-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.2);
  border-radius: 8px;
}

.failing-test-name {
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.25rem;
}

.failing-test-details {
  font-size: 0.875rem;
  color: #a0aec0;
}

.empty-state {
  padding: 4rem 2rem;
  text-align: center;
  color: #a0aec0;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto 1rem;
  opacity: 0.5;
  color: #718096;
}

.empty-subtitle {
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.btn-secondary {
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.recent-executions-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
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
  background: rgba(79, 172, 254, 0.1);
}

.recent-executions-table th {
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  color: #ffffff;
  font-size: 0.875rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.recent-executions-table td {
  padding: 1rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  color: #e2e8f0;
  font-size: 0.875rem;
}

.execution-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-badge.status-passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.status-badge.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-badge.status-partial {
  background: rgba(237, 137, 54, 0.2);
  color: #ed8936;
  border: 1px solid rgba(237, 137, 54, 0.3);
}

.status-badge.status-error {
  background: rgba(245, 101, 101, 0.2);
  color: #f56565;
  border: 1px solid rgba(245, 101, 101, 0.3);
}

.text-muted {
  color: #718096;
  font-style: italic;
}

.btn-icon {
  padding: 0.5rem;
  background: transparent;
  border: none;
  cursor: pointer;
  border-radius: 6px;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.2s;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
}
</style>

