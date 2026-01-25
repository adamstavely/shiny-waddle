<template>
  <div class="application-dashboard">
    <div v-if="loading" class="loading">Loading application dashboard...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && dashboardData" class="dashboard">
      <!-- Header -->
      <div class="dashboard-header">
        <div class="header-content">
          <div>
            <Breadcrumb :items="breadcrumbItems" />
            <h1 class="page-title">{{ applicationName }} Dashboard</h1>
            <p class="page-description">Compliance metrics and test results for this application</p>
          </div>
          <div class="header-actions">
            <button @click="refreshDashboard" class="action-btn" :disabled="isRefreshing">
              <RefreshCw class="action-icon" :class="{ spinning: isRefreshing }" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <!-- Overall Score -->
      <OverallScore :score="dashboardData.overallCompliance" />

      <!-- Key Metrics -->
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-icon">
            <TestTube />
          </div>
          <div class="metric-content">
            <div class="metric-label">Total Tests</div>
            <div class="metric-value">{{ dashboardData.totalTests }}</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon passed">
            <CheckCircle2 />
          </div>
          <div class="metric-content">
            <div class="metric-label">Passed</div>
            <div class="metric-value passed">{{ dashboardData.passedTests }}</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon failed">
            <X />
          </div>
          <div class="metric-content">
            <div class="metric-label">Failed</div>
            <div class="metric-value failed">{{ dashboardData.failedTests }}</div>
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-icon">
            <AlertTriangle />
          </div>
          <div class="metric-content">
            <div class="metric-label">Open Violations</div>
            <div class="metric-value violations">{{ dashboardData.openViolations }}</div>
          </div>
        </div>
      </div>

      <!-- Category Scores -->
      <div class="section">
        <h2 class="section-title">
          <BarChart3 class="section-icon" />
          Compliance by Category
        </h2>
        <CategoryScores :categories="dashboardData.scoresByCategory" />
      </div>

      <!-- Test Results -->
      <div class="section">
        <h2 class="section-title">
          <FileText class="section-icon" />
          Recent Test Results
        </h2>
        <TestResultsTable :results="dashboardData.recentTestResults" />
      </div>

      <!-- Trends -->
      <div class="trends-section">
        <h2 class="section-title">
          <TrendingUp class="section-icon" />
          Compliance Trends
        </h2>
        <div class="trends-grid">
          <div class="trend-card">
            <h3 class="trend-title">Overall Compliance</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="appTrendGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0 }" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="trendPoints"
                  fill="url(#appTrendGradient)"
                  :style="{ stroke: 'var(--color-primary)' }"
                  stroke-width="2"
                />
              </svg>
            </div>
            <div class="trend-stats">
              <span class="trend-change" :class="trendChange >= 0 ? 'positive' : 'negative'">
                {{ trendChange >= 0 ? '+' : '' }}{{ trendChange.toFixed(1) }}%
              </span>
              <span class="trend-period">Last 30 days</span>
            </div>
          </div>

          <div class="trend-card">
            <h3 class="trend-title">Test Execution Frequency</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="execGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0 }" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="executionTrendPoints"
                  fill="url(#execGradient)"
                  :style="{ stroke: 'var(--color-secondary)' }"
                  stroke-width="2"
                />
              </svg>
            </div>
            <div class="trend-stats">
              <span class="trend-value">{{ dashboardData.avgTestsPerDay }}/day</span>
              <span class="trend-period">Average</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Test Suites -->
      <div class="section">
        <h2 class="section-title">
          <FolderOpen class="section-icon" />
          Test Suites
        </h2>
        <div class="test-suites-list">
          <div
            v-for="suite in dashboardData.testSuites"
            :key="suite.id"
            class="suite-card"
            @click="viewTestSuite(suite.id)"
          >
            <div class="suite-header">
              <h3 class="suite-name">{{ suite.name }}</h3>
              <span class="suite-status" :class="`status-${suite.status}`">
                {{ suite.status }}
              </span>
            </div>
            <div class="suite-stats">
              <span class="stat">{{ suite.testCount }} tests</span>
              <span class="stat score" :class="getScoreClass(suite.score)">
                {{ suite.score }}% compliance
              </span>
            </div>
            <div class="suite-meta">
              Last run: {{ formatDate(suite.lastRun) }}
            </div>
          </div>
        </div>
      </div>

      <!-- Violations Summary -->
      <div v-if="dashboardData.recentViolations && dashboardData.recentViolations.length > 0" class="section">
        <h2 class="section-title">
          <Shield class="section-icon" />
          Recent Violations
        </h2>
        <div class="violations-list">
          <div
            v-for="violation in dashboardData.recentViolations"
            :key="violation.id"
            class="violation-item"
            @click="viewViolation(violation.id)"
          >
            <AlertTriangle class="violation-icon" :class="`icon-${violation.severity}`" />
            <div class="violation-content">
              <h4 class="violation-title">{{ violation.title }}</h4>
              <p class="violation-meta">{{ violation.type }} • {{ formatDate(violation.detectedAt) }}</p>
            </div>
            <span class="violation-severity" :class="`badge-${violation.severity}`">
              {{ violation.severity }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import axios from 'axios';
import {
  RefreshCw,
  TestTube,
  CheckCircle2,
  X,
  AlertTriangle,
  BarChart3,
  FileText,
  TrendingUp,
  FolderOpen,
  Shield
} from 'lucide-vue-next';
import OverallScore from '../components/OverallScore.vue';
import CategoryScores from '../components/CategoryScores.vue';
import TestResultsTable from '../components/TestResultsTable.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import { useApiDataAuto } from '../composables/useApiData';

const route = useRoute();
const router = useRouter();

const applicationId = computed(() => route.params.id as string);
const applicationName = computed(() => {
  // In a real app, this would come from the API
  const appNames: Record<string, string> = {
    'research-tracker-api': 'Research Tracker API',
    'user-service': 'User Service',
    'data-pipeline': 'Data Pipeline'
  };
  return appNames[applicationId.value] || applicationId.value;
});

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Dashboard', to: '/dashboard' },
  { label: applicationName.value }
]);

const isRefreshing = ref(false);

// Use composable for API data fetching
const { data: dashboardData, loading, error, reload } = useApiDataAuto(
  async () => {
    // In a real app, this would be: `/api/dashboard/app/${applicationId.value}`
    // For now, we'll use mock data
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      overallCompliance: 95,
      totalTests: 24,
      passedTests: 23,
      failedTests: 1,
      openViolations: 2,
      scoresByCategory: {
        'Access Control': 98,
        'Contract': 92,
        'Dataset Health': 100
      },
      recentTestResults: [
        {
          testName: 'PDP Decision: admin accessing report',
          status: 'passed',
          timestamp: new Date(Date.now() - 30 * 60 * 1000)
        },
        {
          testName: 'Query Validation: viewer executing Get all reports',
          status: 'passed',
          timestamp: new Date(Date.now() - 35 * 60 * 1000)
        },
        {
          testName: 'Contract: No Raw Email Export',
          status: 'failed',
          timestamp: new Date(Date.now() - 40 * 60 * 1000)
        }
      ],
      avgTestsPerDay: 12,
      testSuites: [
        {
          id: '1',
          name: 'Research Tracker API Compliance Tests',
          status: 'passing',
          testCount: 24,
          score: 95,
          lastRun: new Date(Date.now() - 2 * 60 * 60 * 1000)
        }
      ],
      recentViolations: [
        {
          id: '1',
          title: 'Unauthorized Access to Restricted Resource',
          type: 'access-control',
          severity: 'critical',
          detectedAt: new Date(Date.now() - 2 * 60 * 60 * 1000)
        },
        {
          id: '2',
          title: 'Disallowed Join Operation',
          type: 'dlp',
          severity: 'medium',
          detectedAt: new Date(Date.now() - 8 * 60 * 60 * 1000)
        }
      ]
    };
  },
  {
    initialData: null,
    errorMessage: 'Failed to load application dashboard',
  }
);

const refreshDashboard = async () => {
  isRefreshing.value = true;
  await reload();
  setTimeout(() => {
    isRefreshing.value = false;
  }, 1000);
};

const trendPoints = computed(() => {
  // Mock trend data - in real app, this would come from API
  return '0,180 50,170 100,160 150,150 200,140 250,130 300,125 350,120 400,115';
});

const executionTrendPoints = computed(() => {
  // Mock execution trend data
  return '0,190 50,185 100,180 150,175 200,170 250,165 300,160 350,155 400,150';
});

const trendChange = computed(() => {
  // Mock trend change - in real app, this would be calculated from historical data
  return 5.2;
});

const viewTestSuite = (id: string) => {
  router.push(`/tests/${id}`);
};

const viewViolation = (id: string) => {
  router.push(`/violations/${id}`);
};

const formatDate = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / (24 * 60 * 60 * 1000));
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

onMounted(() => {
  loadDashboard();
  window.addEventListener('refresh-dashboard', loadDashboard);
});

onBeforeUnmount(() => {
  window.removeEventListener('refresh-dashboard', loadDashboard);
});
</script>

<style scoped>
.application-dashboard {
  width: 100%;
}

.dashboard {
  max-width: 1400px;
  margin: 0 auto;
}

.dashboard-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}


.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover:not(:disabled) {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.action-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.action-icon {
  width: 18px;
  height: 18px;
}

.action-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: 32px;
}

.metric-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.metric-icon {
  width: 48px;
  height: 48px;
  border-radius: var(--border-radius-full);
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--color-info-bg);
  color: var(--color-primary);
  flex-shrink: 0;
}

.metric-icon svg {
  width: 24px;
  height: 24px;
}

.metric-icon.passed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.metric-icon.failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.metric-content {
  flex: 1;
}

.metric-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.metric-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.metric-value.passed {
  color: var(--color-success);
}

.metric-value.failed {
  color: var(--color-error);
}

.metric-value.violations {
  color: var(--color-warning);
}

.section {
  margin-bottom: 40px;
  position: relative;
  z-index: 1;
}

.section-title {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.section-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.trends-section {
  margin-top: 40px;
  margin-bottom: 40px;
  position: relative;
  z-index: 1;
}

.trends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: var(--spacing-lg);
  position: relative;
}

.trend-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.trend-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.trend-chart {
  width: 100%;
  height: 200px;
  margin-bottom: 16px;
}

.chart-svg {
  width: 100%;
  height: 100%;
}

.trend-stats {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.trend-change {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
}

.trend-change.positive {
  color: var(--color-success);
}

.trend-change.negative {
  color: var(--color-error);
}

.trend-value {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-primary);
}

.trend-period {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.test-suites-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--spacing-xl);
  position: relative;
  z-index: 1;
}

.suite-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.suite-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.suite-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.suite-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.suite-status {
  padding: var(--spacing-xs) 10px;
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-passing {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-failing {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.suite-stats {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.suite-stats .stat {
  color: var(--color-text-secondary);
}

.suite-stats .stat.score {
  font-weight: var(--font-weight-semibold);
}

.score-high {
  color: var(--color-success);
}

.score-medium {
  color: var(--color-warning);
}

.score-low {
  color: var(--color-error);
}

.suite-meta {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.violations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.violation-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left: 4px solid;
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  cursor: pointer;
  transition: var(--transition-all);
}

.violation-item:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateX(4px);
}

.violation-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.icon-critical {
  color: var(--color-error);
}

.icon-high {
  color: var(--color-warning);
}

.icon-medium {
  color: var(--color-primary);
}

.violation-content {
  flex: 1;
}

.violation-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.violation-meta {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin: 0;
}

.violation-severity {
  padding: var(--spacing-xs) 10px;
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.badge-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.badge-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.badge-medium {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.loading {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-primary);
  font-size: var(--font-size-xl);
}

.error {
  text-align: center;
  padding: var(--spacing-xl);
  color: var(--color-error);
  font-size: var(--font-size-xl);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
  margin: var(--spacing-xl) auto;
  max-width: 600px;
}

/* Responsive Styles */
@media (max-width: 767px) {
  .dashboard-header {
    margin-bottom: 24px;
  }
  
  .header-content {
    flex-direction: column;
    gap: var(--spacing-md);
  }
  
  .page-title {
    font-size: var(--font-size-2xl);
  }
  
  .page-description {
    font-size: var(--font-size-base);
  }
  
  .header-actions {
    width: 100%;
  }
  
  .action-btn {
    flex: 1;
    justify-content: center;
  }
  
  .metrics-grid {
    grid-template-columns: 1fr;
    gap: var(--spacing-sm);
    margin-bottom: var(--spacing-lg);
  }
  
  .metric-card {
    padding: var(--spacing-md);
  }
  
  .metric-icon {
    width: 40px;
    height: 40px;
  }
  
  .metric-icon svg {
    width: 20px;
    height: 20px;
  }
  
  .metric-value {
    font-size: var(--font-size-xl);
  }
  
  .section {
    margin-bottom: 32px;
  }
  
  .section-title {
    font-size: var(--font-size-2xl);
    margin-bottom: var(--spacing-md);
  }
  
  .trends-grid {
    grid-template-columns: 1fr;
    gap: var(--spacing-md);
  }
  
  .trend-card {
    padding: var(--spacing-md);
  }
  
  .trend-chart {
    height: 150px;
  }
  
  .test-suites-list {
    grid-template-columns: 1fr;
    gap: var(--spacing-sm);
  }
  
  .suite-card {
    padding: var(--spacing-md);
  }
  
  .violation-item {
    padding: var(--spacing-sm);
    flex-direction: column;
    align-items: flex-start;
    gap: var(--spacing-sm);
  }
}

@media (min-width: 768px) and (max-width: 1023px) {
  .metrics-grid {
    grid-template-columns: repeat(2, 1fr);
    gap: var(--spacing-md);
  }
  
  .trends-grid {
    grid-template-columns: 1fr;
  }
  
  .test-suites-list {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .page-title {
    font-size: var(--font-size-2xl);
  }
}

@media (min-width: 1024px) {
  .metrics-grid {
    grid-template-columns: repeat(4, 1fr);
  }
  
  .trends-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>

