<template>
  <div class="team-dashboard">
    <div v-if="loading" class="loading">Loading team dashboard...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && dashboardData" class="dashboard">
      <!-- Header -->
      <div class="dashboard-header">
        <div class="header-content">
          <div>
            <Breadcrumb :items="breadcrumbItems" />
            <h1 class="page-title">{{ teamName }} Dashboard</h1>
            <p class="page-description">Compliance metrics and test results for this team</p>
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
            <Layers />
          </div>
          <div class="metric-content">
            <div class="metric-label">Applications</div>
            <div class="metric-value">{{ dashboardData.applicationCount }}</div>
          </div>
        </div>
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
            <div class="metric-label">Pass Rate</div>
            <div class="metric-value passed">{{ dashboardData.passRate }}%</div>
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

      <!-- Applications Grid -->
      <div class="section">
        <h2 class="section-title">Applications</h2>
        <div class="applications-grid">
          <div
            v-for="app in dashboardData.applications"
            :key="app.id"
            class="app-card"
            @click="viewApplication(app.id)"
          >
            <div class="app-header">
              <h3 class="app-name">{{ app.name }}</h3>
              <span class="app-status" :class="`status-${app.status}`">
                {{ app.status }}
              </span>
            </div>
            <div class="app-score">
              <div class="score-circle" :class="getScoreClass(app.score)">
                <span class="score-value">{{ app.score }}%</span>
              </div>
            </div>
            <div class="app-stats">
              <div class="stat">
                <span class="stat-label">Tests</span>
                <span class="stat-value">{{ app.testCount }}</span>
              </div>
              <div class="stat">
                <span class="stat-label">Violations</span>
                <span class="stat-value" :class="app.violations > 0 ? 'violations' : ''">
                  {{ app.violations }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Category Scores -->
      <div class="section">
        <h2 class="section-title">Compliance by Category</h2>
        <CategoryScores :categories="dashboardData.scoresByCategory" />
      </div>

      <!-- Test Results -->
      <div class="section">
        <h2 class="section-title">Recent Test Results</h2>
        <TestResultsTable :results="dashboardData.recentTestResults" />
      </div>

      <!-- Trends -->
      <div class="trends-section">
        <h2 class="section-title">Team Compliance Trends</h2>
        <div class="trends-grid">
          <div class="trend-card">
            <h3 class="trend-title">Overall Compliance</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="teamTrendGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0 }" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="trendPoints"
                  fill="url(#teamTrendGradient)"
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
            <h3 class="trend-title">Applications Compliance</h3>
            <div class="trend-chart">
              <svg class="chart-svg" viewBox="0 0 400 200" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="appsGradient" x1="0%" y1="0%" x2="0%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.3 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0 }" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="applicationsTrendPoints"
                  fill="url(#appsGradient)"
                  :style="{ stroke: 'var(--color-secondary)' }"
                  stroke-width="2"
                />
              </svg>
            </div>
            <div class="trend-stats">
              <span class="trend-value">{{ dashboardData.avgCompliance }}%</span>
              <span class="trend-period">Average</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Team Members -->
      <div v-if="dashboardData.teamMembers" class="section">
        <h2 class="section-title">Team Members</h2>
        <div class="members-list">
          <div
            v-for="member in dashboardData.teamMembers"
            :key="member.id"
            class="member-card"
          >
            <div class="member-avatar">
              {{ member.initials }}
            </div>
            <div class="member-info">
              <div class="member-name">{{ member.name }}</div>
              <div class="member-role">{{ member.role }}</div>
            </div>
            <div class="member-stats">
              <div class="stat">
                <span class="stat-label">Tests Run</span>
                <span class="stat-value">{{ member.testsRun }}</span>
              </div>
            </div>
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
  Layers,
  TestTube,
  CheckCircle2,
  AlertTriangle
} from 'lucide-vue-next';
import OverallScore from '../components/OverallScore.vue';
import CategoryScores from '../components/CategoryScores.vue';
import TestResultsTable from '../components/TestResultsTable.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import { LayoutDashboard } from 'lucide-vue-next';
import { useApiDataAuto } from '../composables/useApiData';

const route = useRoute();
const router = useRouter();

const teamId = computed(() => route.params.id as string);
const teamName = computed(() => {
  // In a real app, this would come from the API
  const teamNames: Record<string, string> = {
    'research-platform': 'Research Platform',
    'platform-team': 'Platform Team',
    'data-engineering': 'Data Engineering'
  };
  return teamNames[teamId.value] || teamId.value;
});

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Dashboard', to: '/dashboard' },
  { label: teamName.value }
]);

const isRefreshing = ref(false);

// Use composable for API data fetching
const { data: dashboardData, loading, error, reload } = useApiDataAuto(
  async () => {
    // In a real app, this would be: `/api/dashboard/team/${teamId.value}`
    // For now, we'll use mock data
    await new Promise(resolve => setTimeout(resolve, 500));
    
    return {
      overallCompliance: 88,
      applicationCount: 3,
      totalTests: 74,
      passRate: 89,
      openViolations: 5,
      scoresByCategory: {
        'Access Control': 92,
        'Contract': 85,
        'Dataset Health': 90
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
      avgCompliance: 88,
      applications: [
        {
          id: 'research-tracker-api',
          name: 'Research Tracker API',
          status: 'passing',
          score: 95,
          testCount: 24,
          violations: 2
        },
        {
          id: 'user-service',
          name: 'User Service',
          status: 'failing',
          score: 72,
          testCount: 18,
          violations: 3
        },
        {
          id: 'data-pipeline',
          name: 'Data Pipeline',
          status: 'passing',
          score: 88,
          testCount: 32,
          violations: 0
        }
      ],
      teamMembers: [
        {
          id: '1',
          name: 'John Doe',
          initials: 'JD',
          role: 'Senior Engineer',
          testsRun: 45
        },
        {
          id: '2',
          name: 'Jane Smith',
          initials: 'JS',
          role: 'Engineering Manager',
          testsRun: 23
        },
        {
          id: '3',
          name: 'Bob Johnson',
          initials: 'BJ',
          role: 'Software Engineer',
          testsRun: 38
        }
      ]
    };
  },
  {
    initialData: null,
    errorMessage: 'Failed to load team dashboard',
  }
);

const refreshDashboard = async () => {
  isRefreshing.value = true;
  await reload();
  setTimeout(() => {
    isRefreshing.value = false;
  }, 1000);
};

const viewApplication = (appId: string) => {
  router.push(`/dashboard/app/${appId}`);
};

const trendPoints = computed(() => {
  // Mock trend data
  return '0,180 50,175 100,170 150,165 200,160 250,155 300,150 350,145 400,140';
});

const applicationsTrendPoints = computed(() => {
  // Mock applications trend data
  return '0,170 50,168 100,165 150,162 200,160 250,158 300,155 350,152 400,150';
});

const trendChange = computed(() => {
  // Mock trend change
  return 3.8;
});

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
.team-dashboard {
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
  font-size: var(--font-size-4xl);
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
  padding: var(--spacing-sm) var(--spacing-xl);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover:not(:disabled) {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.action-btn:disabled {
  opacity: var(--opacity-disabled);
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
  gap: var(--spacing-xl);
  margin-bottom: var(--spacing-xl);
}

.metric-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.metric-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
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

.metric-value.violations {
  color: var(--color-warning);
}

.section {
  margin-bottom: 40px;
}

.section-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.applications-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--spacing-xl);
}

.app-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.app-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-md);
}

.app-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.app-status {
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

.app-score {
  display: flex;
  justify-content: center;
  margin-bottom: var(--spacing-md);
}

.score-circle {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 4px solid;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-bold);
}

.score-circle.score-high {
  border-color: var(--color-success);
  color: var(--color-success);
}

.score-circle.score-medium {
  border-color: var(--color-warning);
  color: var(--color-warning);
}

.score-circle.score-low {
  border-color: var(--color-error);
  color: var(--color-error);
}

.score-value {
  font-size: var(--font-size-2xl);
}

.app-stats {
  display: flex;
  justify-content: space-around;
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.app-stats .stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-xs);
}

.app-stats .stat-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.app-stats .stat-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.app-stats .stat-value.violations {
  color: var(--color-warning);
}

.trends-section {
  margin-top: 40px;
}

.trends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: var(--spacing-lg);
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
  margin-bottom: var(--spacing-md);
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

.members-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: var(--spacing-md);
}

.member-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.member-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: var(--gradient-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--color-bg-primary);
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-sm);
  flex-shrink: 0;
}

.member-info {
  flex: 1;
}

.member-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: 2px;
}

.member-role {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.member-stats {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
}

.member-stats .stat {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: var(--spacing-xs);
}

.member-stats .stat-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.member-stats .stat-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.loading {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-primary);
  font-size: var(--font-size-xl);
}

.error {
  text-align: center;
  padding: var(--spacing-lg);
  color: var(--color-error);
  font-size: var(--font-size-xl);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.5;
  border-radius: var(--border-radius-md);
  margin: var(--spacing-lg) auto;
  max-width: 600px;
}
</style>

