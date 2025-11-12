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
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.3" />
                    <stop offset="100%" style="stop-color:#4facfe;stop-opacity:0" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="trendPoints"
                  fill="url(#teamTrendGradient)"
                  stroke="#4facfe"
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
                    <stop offset="0%" style="stop-color:#00f2fe;stop-opacity:0.3" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:0" />
                  </linearGradient>
                </defs>
                <polyline
                  :points="applicationsTrendPoints"
                  fill="url(#appsGradient)"
                  stroke="#00f2fe"
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

const loading = ref(true);
const error = ref<string | null>(null);
const isRefreshing = ref(false);
const dashboardData = ref<any>(null);

const loadDashboard = async () => {
  try {
    loading.value = true;
    error.value = null;
    // In a real app, this would be: `/api/dashboard/team/${teamId.value}`
    // For now, we'll use mock data
    await new Promise(resolve => setTimeout(resolve, 500));
    
    dashboardData.value = {
      overallCompliance: 88,
      applicationCount: 3,
      totalTests: 74,
      passRate: 89,
      openViolations: 5,
      scoresByCategory: {
        'Access Control': 92,
        'Data Behavior': 88,
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
  } catch (err: any) {
    error.value = err.message || 'Failed to load team dashboard';
  } finally {
    loading.value = false;
  }
};

const refreshDashboard = async () => {
  isRefreshing.value = true;
  await loadDashboard();
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
  gap: 24px;
}


.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
  gap: 20px;
  margin-bottom: 32px;
}

.metric-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  align-items: center;
  gap: 16px;
}

.metric-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  flex-shrink: 0;
}

.metric-icon svg {
  width: 24px;
  height: 24px;
}

.metric-icon.passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.metric-content {
  flex: 1;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 4px;
}

.metric-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #ffffff;
}

.metric-value.passed {
  color: #22c55e;
}

.metric-value.violations {
  color: #fbbf24;
}

.section {
  margin-bottom: 40px;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 24px;
}

.applications-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 20px;
}

.app-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.app-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.app-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.app-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.app-status {
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-passing {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failing {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.app-score {
  display: flex;
  justify-content: center;
  margin-bottom: 16px;
}

.score-circle {
  width: 80px;
  height: 80px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 4px solid;
  font-size: 1.25rem;
  font-weight: 700;
}

.score-circle.score-high {
  border-color: #22c55e;
  color: #22c55e;
}

.score-circle.score-medium {
  border-color: #fbbf24;
  color: #fbbf24;
}

.score-circle.score-low {
  border-color: #fc8181;
  color: #fc8181;
}

.score-value {
  font-size: 1.5rem;
}

.app-stats {
  display: flex;
  justify-content: space-around;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.app-stats .stat {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}

.app-stats .stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.app-stats .stat-value {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}

.app-stats .stat-value.violations {
  color: #fbbf24;
}

.trends-section {
  margin-top: 40px;
}

.trends-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 24px;
}

.trend-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.trend-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
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
  font-size: 1.125rem;
  font-weight: 600;
}

.trend-change.positive {
  color: #22c55e;
}

.trend-change.negative {
  color: #fc8181;
}

.trend-value {
  font-size: 1.125rem;
  font-weight: 600;
  color: #4facfe;
}

.trend-period {
  font-size: 0.875rem;
  color: #a0aec0;
}

.members-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 16px;
}

.member-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
  display: flex;
  align-items: center;
  gap: 12px;
}

.member-avatar {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #0f1419;
  font-weight: 600;
  font-size: 0.875rem;
  flex-shrink: 0;
}

.member-info {
  flex: 1;
}

.member-name {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 2px;
}

.member-role {
  font-size: 0.75rem;
  color: #a0aec0;
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
  gap: 2px;
}

.member-stats .stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.member-stats .stat-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.loading {
  text-align: center;
  padding: 50px;
  color: #4facfe;
  font-size: 1.2em;
}

.error {
  text-align: center;
  padding: 20px;
  color: #fc8181;
  font-size: 1.2em;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin: 20px auto;
  max-width: 600px;
}
</style>

