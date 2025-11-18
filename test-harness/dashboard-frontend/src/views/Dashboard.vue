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
          <router-link to="/runs" class="view-all-link">View All</router-link>
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
          <router-link to="/runs" class="quick-action-card">
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
  router.push('/runs');
};

const onboardApp = () => {
  router.push('/applications');
};

const viewRun = (runId: string) => {
  router.push(`/runs?runId=${runId}`);
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
      axios.get('/api/test-batteries'),
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
      axios.get('/api/test-harnesses'),
      axios.get('/api/v1/applications'),
      axios.get('/api/test-suites')
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
  padding: 24px;
}

.page-header {
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

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  font-size: 1rem;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  background: transparent;
  color: #4facfe;
  border: 2px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-state,
.error-state {
  text-align: center;
  padding: 80px 40px;
  color: #a0aec0;
}

.error-state {
  color: #fc8181;
}

.error-icon {
  width: 48px;
  height: 48px;
  margin: 0 auto 16px;
  color: #fc8181;
}

.btn-retry {
  margin-top: 16px;
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
}

.metric-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.metric-header {
  margin-bottom: 12px;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.metric-value {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
}

.metric-value.passed {
  color: #22c55e;
}

.metric-value.failed {
  color: #fc8181;
}

.metric-value.score-high {
  color: #22c55e;
}

.metric-value.score-medium {
  color: #fbbf24;
}

.metric-value.score-low {
  color: #fc8181;
}

.section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 32px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.view-all-link {
  color: #4facfe;
  text-decoration: none;
  font-size: 0.875rem;
  font-weight: 500;
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
  padding: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.runs-table td {
  padding: 12px;
  color: #ffffff;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.run-row {
  cursor: pointer;
  transition: background 0.2s;
}

.run-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-completed,
.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-running {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.score {
  font-weight: 600;
}

.issues-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.issue-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.issue-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.issue-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.priority-badge {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.priority-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.priority-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.issue-domain {
  font-size: 0.875rem;
  color: #a0aec0;
}

.issue-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.issue-app {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.quick-actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.quick-action-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  padding: 24px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  text-decoration: none;
  color: #ffffff;
  transition: all 0.2s;
}

.quick-action-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.batteries-status-grid,
.harnesses-status-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.status-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
  text-align: center;
}

.status-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.status-value.healthy {
  color: #22c55e;
}

.status-value.warning {
  color: #fbbf24;
}

.status-value.error {
  color: #fc8181;
}

.status-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.recent-executions {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.subsection-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.executions-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.execution-item {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.execution-item:hover {
  background: rgba(15, 20, 25, 0.6);
  border-color: rgba(79, 172, 254, 0.4);
}

.execution-battery {
  flex: 1;
  color: #ffffff;
  font-weight: 500;
}

.execution-status {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.execution-status.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.execution-status.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.execution-status.status-running {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.execution-time {
  color: #a0aec0;
  font-size: 0.875rem;
}
</style>

