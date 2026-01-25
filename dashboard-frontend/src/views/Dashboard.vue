<template>
  <div class="dashboard-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Dashboard</h1>
          <p class="page-description">Org-wide view of compliance, applications, and test battery runs</p>
        </div>
        <div class="header-actions">
          <button @click="runBattery" class="btn-primary">
            <PlayCircle class="btn-icon" />
            Run Battery
          </button>
          <button @click="onboardApp" class="btn-secondary">
            <Plus class="btn-icon" />
            Onboard New App
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="loading-state">
      <p>Loading dashboard data...</p>
    </div>

    <!-- Error State -->
    <div v-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadData" class="btn-retry">Retry</button>
    </div>

    <!-- Dashboard Content -->
    <div v-if="!loading && !error" class="dashboard-content">
      <!-- Key Metrics -->
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Overall Compliance Score</span>
          </div>
          <div class="metric-value" :class="getScoreClass(overallComplianceScore)">
            {{ overallComplianceScore }}%
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Applications Passing</span>
          </div>
          <div class="metric-value passed">
            {{ appsPassing }}
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Applications Failing</span>
          </div>
          <div class="metric-value failed">
            {{ appsFailing }}
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-header">
            <span class="metric-label">Total Applications</span>
          </div>
          <div class="metric-value">
            {{ totalApps }}
          </div>
        </div>
      </div>

      <!-- Test Batteries Status -->
      <div class="section">
        <div class="section-header">
          <h2 class="section-title">Test Batteries Status</h2>
          <router-link to="/tests/batteries" class="view-all-link">View All Batteries</router-link>
        </div>
        <div v-if="loadingBatteries" class="loading-state">
          <p>Loading battery status...</p>
        </div>
        <div v-else-if="batteriesError" class="error-state">
          <p>{{ batteriesError }}</p>
        </div>
        <div v-else class="batteries-status-grid">
          <div class="status-card">
            <div class="status-value">{{ totalBatteries }}</div>
            <div class="status-label">Total Batteries</div>
          </div>
          <div class="status-card">
            <div class="status-value healthy">{{ batteriesHealthy }}</div>
            <div class="status-label">Healthy</div>
          </div>
          <div class="status-card">
            <div class="status-value warning">{{ batteriesWarning }}</div>
            <div class="status-label">Warning</div>
          </div>
          <div class="status-card">
            <div class="status-value error">{{ batteriesErrorCount }}</div>
            <div class="status-label">Error</div>
          </div>
        </div>
        <div v-if="!loadingBatteries && !batteriesError && recentBatteryExecutions.length > 0" class="recent-executions">
          <h3 class="subsection-title">Recent Battery Executions</h3>
          <div class="executions-list">
            <div
              v-for="execution in recentBatteryExecutions"
              :key="execution.id"
              class="execution-item"
              @click="viewBattery(execution.batteryId)"
            >
              <span class="execution-battery">{{ execution.batteryName }}</span>
              <span class="execution-status" :class="`status-${execution.status}`">
                {{ execution.status }}
              </span>
              <span class="execution-time">{{ formatTime(execution.timestamp) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Test Harnesses Status -->
      <div class="section">
        <div class="section-header">
          <h2 class="section-title">Test Harnesses Status</h2>
          <router-link to="/tests/harnesses" class="view-all-link">View All Harnesses</router-link>
        </div>
        <div v-if="loadingHarnesses" class="loading-state">
          <p>Loading harness status...</p>
        </div>
        <div v-else-if="harnessesError" class="error-state">
          <p>{{ harnessesError }}</p>
        </div>
        <div v-else class="harnesses-status-grid">
          <div class="status-card">
            <div class="status-value">{{ totalHarnesses }}</div>
            <div class="status-label">Total Harnesses</div>
          </div>
          <div class="status-card">
            <div class="status-value">{{ harnessesWithApps }}</div>
            <div class="status-label">Assigned to Apps</div>
          </div>
          <div class="status-card">
            <div class="status-value">{{ totalApplicationsCovered }}</div>
            <div class="status-label">Applications Covered</div>
          </div>
          <div class="status-card">
            <div class="status-value">{{ totalTestSuites }}</div>
            <div class="status-label">Total Test Suites</div>
          </div>
        </div>
      </div>

      <!-- Recent Test Battery Runs -->
      <div class="section">
        <div class="section-header">
          <h2 class="section-title">Recent Test Battery Runs</h2>
          <router-link to="/tests/history" class="view-all-link">View All</router-link>
        </div>
        <div v-if="recentRuns.length === 0" class="empty-state">
          <p>No recent battery runs</p>
        </div>
        <div v-else class="runs-table">
          <table>
            <thead>
              <tr>
                <th>Battery</th>
                <th>Application</th>
                <th>Status</th>
                <th>Run Time</th>
                <th>Score</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="run in recentRuns"
                :key="run.id"
                @click="viewRun(run.id)"
                class="run-row"
              >
                <td>{{ run.batteryName }}</td>
                <td>{{ run.applicationName }}</td>
                <td>
                  <span class="status-badge" :class="`status-${run.status}`">
                    {{ run.status }}
                  </span>
                </td>
                <td>{{ formatTime(run.timestamp) }}</td>
                <td>
                  <span class="score" :class="getScoreClass(run.score)">
                    {{ run.score }}%
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Top Critical Issues -->
      <div class="section">
        <div class="section-header">
          <h2 class="section-title">Top Critical Issues</h2>
          <router-link to="/applications" class="view-all-link">View All Issues</router-link>
        </div>
        <div v-if="topIssues.length === 0" class="empty-state">
          <p>No critical issues</p>
        </div>
        <div v-else class="issues-list">
          <div
            v-for="issue in topIssues"
            :key="issue.id"
            class="issue-card"
            @click="viewIssue(issue)"
          >
            <div class="issue-header">
              <span class="priority-badge" :class="`priority-${issue.priority}`">
                {{ issue.priority }}
              </span>
              <span class="issue-domain">{{ issue.domain }}</span>
            </div>
            <h3 class="issue-title">{{ issue.title }}</h3>
            <p class="issue-app">{{ issue.applicationName }}</p>
          </div>
        </div>
      </div>

      <!-- Quick Links -->
      <div class="section">
        <h2 class="section-title">Quick Actions</h2>
        <div class="quick-actions-grid">
          <router-link to="/applications" class="quick-action-card">
            <Database class="action-icon" />
            <span>View Applications</span>
          </router-link>
          <router-link to="/test-design-library" class="quick-action-card">
            <BookOpen class="action-icon" />
            <span>Test Design Library</span>
          </router-link>
          <router-link to="/tests/history" class="quick-action-card">
            <PlayCircle class="action-icon" />
            <span>View All Runs</span>
          </router-link>
          <router-link to="/policies" class="quick-action-card">
            <Shield class="action-icon" />
            <span>Policies & Config</span>
          </router-link>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import axios from 'axios';
import {
  PlayCircle,
  Plus,
  AlertTriangle,
  Database,
  BookOpen,
  Shield,
  Battery,
  Layers
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Dashboard' }
];

const loading = ref(true);
const error = ref<string | null>(null);
const overallComplianceScore = ref(0);
const appsPassing = ref(0);
const appsFailing = ref(0);
const totalApps = ref(0);
const recentRuns = ref<any[]>([]);
const topIssues = ref<any[]>([]);

// Test Batteries data
const loadingBatteries = ref(false);
const batteriesError = ref<string | null>(null);
const totalBatteries = ref(0);
const batteriesHealthy = ref(0);
const batteriesWarning = ref(0);
const batteriesErrorCount = ref(0);
const recentBatteryExecutions = ref<any[]>([]);

// Test Harnesses data
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);
const totalHarnesses = ref(0);
const harnessesWithApps = ref(0);
const totalApplicationsCovered = ref(0);
const totalTestSuites = ref(0);

const loadData = async () => {
  try {
    loading.value = true;
    error.value = null;

    // Load dashboard data
    const [appsResponse, runsResponse, issuesResponse] = await Promise.all([
      axios.get('/api/v1/applications'),
      axios.get('/api/v1/runs?limit=10'),
      axios.get('/api/v1/applications/issues?limit=10&priority=critical,high')
    ]);

    // Load test batteries and harnesses data
    await Promise.all([
      loadBatteriesData(),
      loadHarnessesData()
    ]);

    const apps = appsResponse.data || [];
    totalApps.value = apps.length;
    
    // Calculate compliance metrics
    let totalScore = 0;
    let passing = 0;
    let failing = 0;
    
    apps.forEach((app: any) => {
      const score = app.complianceScore || 0;
      totalScore += score;
      if (score >= 90) {
        passing++;
      } else if (score < 70) {
        failing++;
      }
    });

    overallComplianceScore.value = apps.length > 0 ? Math.round(totalScore / apps.length) : 0;
    appsPassing.value = passing;
    appsFailing.value = failing;

    recentRuns.value = (runsResponse.data || []).map((run: any) => ({
      ...run,
      timestamp: new Date(run.timestamp || run.createdAt)
    }));

    topIssues.value = issuesResponse.data || [];
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load dashboard data';
    console.error('Error loading dashboard:', err);
  } finally {
    loading.value = false;
  }
};

const runBattery = () => {
  router.push('/tests/history');
};

const onboardApp = () => {
  router.push('/applications');
};

const viewRun = (runId: string) => {
  router.push(`/tests/history?runId=${runId}`);
};

const viewIssue = (issue: any) => {
  router.push(`/applications/${issue.applicationId}?tab=issues`);
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatTime = (date: Date | string): string => {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};

const loadBatteriesData = async () => {
  try {
    loadingBatteries.value = true;
    batteriesError.value = null;
    
    const [batteriesResponse, runsResponse] = await Promise.all([
      axios.get('/api/v1/test-batteries'),
      axios.get('/api/v1/runs?limit=20')
    ]);
    
    const batteries = batteriesResponse.data || [];
    const runs = runsResponse.data || [];
    
    totalBatteries.value = batteries.length;
    
    // Calculate battery health status
    let healthy = 0;
    let warning = 0;
    let error = 0;
    
    batteries.forEach((battery: any) => {
      // Get recent runs for this battery
      const batteryRuns = runs.filter((r: any) => r.batteryId === battery.id);
      if (batteryRuns.length === 0) {
        warning++; // No runs yet
      } else {
        const latestRun = batteryRuns[0];
        if (latestRun.status === 'completed' && latestRun.score >= 90) {
          healthy++;
        } else if (latestRun.status === 'failed' || (latestRun.status === 'completed' && latestRun.score < 70)) {
          error++;
        } else {
          warning++;
        }
      }
    });
    
    batteriesHealthy.value = healthy;
    batteriesWarning.value = warning;
    batteriesErrorCount.value = error;
    
    // Get recent battery executions
    recentBatteryExecutions.value = runs
      .filter((r: any) => r.batteryId && r.batteryName)
      .slice(0, 5)
      .map((run: any) => ({
        ...run,
        timestamp: new Date(run.timestamp || run.createdAt)
      }));
  } catch (err: any) {
    batteriesError.value = err.response?.data?.message || 'Failed to load battery data';
    console.error('Error loading batteries:', err);
  } finally {
    loadingBatteries.value = false;
  }
};

const loadHarnessesData = async () => {
  try {
    loadingHarnesses.value = true;
    harnessesError.value = null;
    
    const [harnessesResponse, appsResponse, suitesResponse] = await Promise.all([
      axios.get('/api/v1/test-harnesses'),
      axios.get('/api/v1/applications'),
      axios.get('/api/v1/test-suites')
    ]);
    
    const harnesses = harnessesResponse.data || [];
    const apps = appsResponse.data || [];
    const suites = suitesResponse.data || [];
    
    totalHarnesses.value = harnesses.length;
    
    // Count harnesses assigned to applications
    const harnessIdsWithApps = new Set<string>();
    apps.forEach((app: any) => {
      if (app.testHarnessIds && Array.isArray(app.testHarnessIds)) {
        app.testHarnessIds.forEach((id: string) => harnessIdsWithApps.add(id));
      }
    });
    harnessesWithApps.value = harnessIdsWithApps.size;
    
    // Count total applications covered
    const appIdsWithHarnesses = new Set<string>();
    apps.forEach((app: any) => {
      if (app.testHarnessIds && app.testHarnessIds.length > 0) {
        appIdsWithHarnesses.add(app.id);
      }
    });
    totalApplicationsCovered.value = appIdsWithHarnesses.size;
    
    // Count total test suites
    totalTestSuites.value = suites.length;
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load harness data';
    console.error('Error loading harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const viewBattery = (batteryId: string) => {
  router.push(`/tests/batteries/${batteryId}`);
};

onMounted(() => {
  loadData();
});
</script>

<style scoped>
.dashboard-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: var(--spacing-lg);
}

.page-header {
  margin-bottom: var(--spacing-xl);
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

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
  font-size: var(--font-size-base);
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-secondary {
  background: transparent;
  color: var(--color-primary);
  border: var(--border-width-medium) solid var(--border-color-secondary);
}

.btn-secondary:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-state,
.error-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.error-state {
  color: var(--color-error);
}

.error-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto var(--spacing-md);
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--color-info-bg);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  cursor: pointer;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.metric-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.metric-header {
  margin-bottom: var(--spacing-md);
}

.metric-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.metric-value {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.metric-value.passed {
  color: var(--color-success);
}

.metric-value.failed {
  color: var(--color-error);
}

.metric-value.score-high {
  color: var(--color-success);
}

.metric-value.score-medium {
  color: var(--color-warning);
}

.metric-value.score-low {
  color: var(--color-error);
}

.section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-xl);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.view-all-link {
  color: var(--color-primary);
  text-decoration: none;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.view-all-link:hover {
  text-decoration: underline;
}

.runs-table {
  overflow-x: auto;
}

.runs-table table {
  width: 100%;
  border-collapse: collapse;
}

.runs-table th {
  text-align: left;
  padding: var(--spacing-sm);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-secondary);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.runs-table td {
  padding: var(--spacing-sm);
  color: var(--color-text-primary);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.run-row {
  cursor: pointer;
  transition: var(--transition-base);
}

.run-row:hover {
  background: var(--border-color-muted);
  opacity: 0.5;
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-completed,
.status-passed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-running {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.score {
  font-weight: 600;
}

.issues-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.issue-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  cursor: pointer;
  transition: var(--transition-all);
}

.issue-card:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
}

.issue-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.priority-badge {
  padding: var(--spacing-xs) 10px;
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: uppercase;
}

.priority-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.priority-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.issue-domain {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.issue-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.issue-app {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.quick-actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.quick-action-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  text-decoration: none;
  color: var(--color-text-primary);
  transition: var(--transition-all);
}

.quick-action-card:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: var(--color-primary);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.batteries-status-grid,
.harnesses-status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.status-card {
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  text-align: center;
}

.status-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.status-value.healthy {
  color: var(--color-success);
}

.status-value.warning {
  color: var(--color-warning);
}

.status-value.error {
  color: var(--color-error);
}

.status-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.recent-executions {
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.subsection-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.executions-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.execution-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
  cursor: pointer;
  transition: var(--transition-all);
}

.execution-item:hover {
  background: var(--color-bg-overlay-light);
  border-color: var(--border-color-primary-hover);
}

.execution-battery {
  flex: 1;
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.execution-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.execution-status.status-completed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.execution-status.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.execution-status.status-running {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.execution-time {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}
</style>

