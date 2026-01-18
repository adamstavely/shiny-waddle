<template>
  <div class="runs-reports-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Runs & Reports</h1>
          <p class="page-description">View test battery executions, reports, and trends</p>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs-container">
      <div class="tabs">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          @click="activeTab = tab.id"
          :class="['tab-button', { active: activeTab === tab.id }]"
        >
          <component :is="tab.icon" class="tab-icon" />
          {{ tab.label }}
        </button>
      </div>
    </div>

    <!-- Tab Content -->
    <div class="tab-content">
      <!-- Runs Tab -->
      <div v-if="activeTab === 'runs'" class="tab-panel">
        <div class="filters">
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search runs..."
            class="search-input"
          />
          <Dropdown
            v-model="filterApplication"
            :options="applicationOptions"
            placeholder="All Applications"
            class="filter-dropdown"
          />
          <Dropdown
            v-model="filterBattery"
            :options="batteryOptions"
            placeholder="All Batteries"
            class="filter-dropdown"
          />
          <Dropdown
            v-model="filterStatus"
            :options="statusOptions"
            placeholder="All Statuses"
            class="filter-dropdown"
          />
          <input
            v-model="filterDateFrom"
            type="date"
            class="filter-date"
            placeholder="From Date"
          />
          <input
            v-model="filterDateTo"
            type="date"
            class="filter-date"
            placeholder="To Date"
          />
        </div>

        <div v-if="loadingRuns" class="loading-state">
          <p>Loading runs...</p>
        </div>
        <div v-else-if="runsError" class="error-state">
          <p>{{ runsError }}</p>
        </div>
        <div v-else class="runs-table-container">
          <table class="runs-table">
            <thead>
              <tr>
                <th>Battery</th>
                <th>Application</th>
                <th>Harnesses</th>
                <th>Environment</th>
                <th>Status</th>
                <th>Score</th>
                <th>Run Time</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="run in filteredRuns"
                :key="run.id"
                class="run-row"
                @click="viewRunDetails(run.id)"
              >
                <td>{{ run.batteryName }}</td>
                <td>{{ run.applicationName }}</td>
                <td>
                  <div class="harnesses-list">
                    <span
                      v-for="harness in run.harnesses"
                      :key="harness.id"
                      class="harness-tag"
                    >
                      {{ harness.name }}
                    </span>
                  </div>
                </td>
                <td>{{ run.environment || 'N/A' }}</td>
                <td>
                  <span class="status-badge" :class="`status-${run.status}`">
                    {{ run.status }}
                  </span>
                </td>
                <td>
                  <span class="score" :class="getScoreClass(run.score)">
                    {{ run.score }}%
                  </span>
                </td>
                <td>{{ formatTime(run.timestamp) }}</td>
                <td>
                  <div class="actions-cell" @click.stop>
                    <button @click="viewRunDetails(run.id)" class="btn-link">
                      View
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <div v-if="filteredRuns.length === 0" class="empty-state">
            <p>No runs found</p>
          </div>
        </div>
      </div>

      <!-- Reports Tab -->
      <div v-if="activeTab === 'reports'" class="tab-panel">
        <div class="reports-section">
          <div class="section-header">
            <h2 class="section-title">Compliance Snapshots</h2>
            <button @click="createSnapshot" class="btn-primary" :disabled="creatingSnapshot">
              <Plus class="btn-icon" />
              {{ creatingSnapshot ? 'Creating...' : 'Create Snapshot' }}
            </button>
          </div>
          
          <div v-if="snapshotsLoading" class="loading-state">
            <p>Loading snapshots...</p>
          </div>
          <div v-else-if="snapshotsError" class="error-state">
            <p>{{ snapshotsError }}</p>
          </div>
          <div v-else-if="snapshots.length === 0" class="empty-state">
            <p>No compliance snapshots yet</p>
            <p class="empty-description">Create a snapshot to capture the current compliance state</p>
          </div>
          <div v-else class="snapshots-list">
            <div
              v-for="snapshot in snapshots"
              :key="snapshot.id"
              class="snapshot-card"
              @click="viewSnapshot(snapshot.id)"
            >
              <div class="snapshot-header">
                <h3 class="snapshot-name">{{ snapshot.name }}</h3>
                <span class="snapshot-score" :class="getScoreClass(snapshot.overallScore)">
                  {{ snapshot.overallScore }}%
                </span>
              </div>
              <div class="snapshot-meta">
                <span>{{ formatTime(snapshot.timestamp) }}</span>
                <span>{{ snapshot.applications.length }} application{{ snapshot.applications.length !== 1 ? 's' : '' }}</span>
              </div>
            </div>
          </div>
        </div>
        
        <div class="reports-section mt-xl">
          <h2 class="section-title">Saved Reports</h2>
          <Reports />
        </div>
      </div>

      <!-- Trends Tab -->
      <div v-if="activeTab === 'trends'" class="tab-panel">
        <div class="trends-header">
          <h2 class="section-title">Compliance Trends</h2>
          <div class="trend-filters">
            <Dropdown
              v-model="trendFilterApplication"
              :options="applicationOptions"
              placeholder="All Applications"
              class="filter-dropdown"
            />
            <input
              v-model="trendDays"
              type="number"
              min="7"
              max="365"
              placeholder="Days"
              class="filter-input"
            />
          </div>
        </div>
        <div class="trends-container">
          <div class="trend-section">
            <h3 class="trend-title">Overall Compliance Trend</h3>
            <ComplianceTrendChart
              :application-id="trendFilterApplication || undefined"
              :days="trendDays || 30"
            />
          </div>
          <div class="trend-section">
            <h3 class="trend-title">Posture Trends by Domain</h3>
            <div class="domain-charts-grid">
              <div class="domain-chart-item">
                <h4 class="domain-chart-title">Data Contracts</h4>
                <DomainTrendChart
                  domain="Data Contracts"
                  :application-id="trendFilterApplication || undefined"
                  :days="trendDays || 30"
                />
              </div>
              <div class="domain-chart-item">
                <h4 class="domain-chart-title">IAM</h4>
                <DomainTrendChart
                  domain="IAM"
                  :application-id="trendFilterApplication || undefined"
                  :days="trendDays || 30"
                />
              </div>
              <div class="domain-chart-item">
                <h4 class="domain-chart-title">API Security</h4>
                <DomainTrendChart
                  domain="API Security"
                  :application-id="trendFilterApplication || undefined"
                  :days="trendDays || 30"
                />
              </div>
              <div class="domain-chart-item">
                <h4 class="domain-chart-title">Platform Config</h4>
                <DomainTrendChart
                  domain="Platform Config"
                  :application-id="trendFilterApplication || undefined"
                  :days="trendDays || 30"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import axios from 'axios';
import {
  PlayCircle,
  FileText,
  TrendingUp,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';
import Reports from './Reports.vue';
import ComplianceTrendChart from '../components/ComplianceTrendChart.vue';
import DomainTrendChart from '../components/DomainTrendChart.vue';

const route = useRoute();
const router = useRouter();

const activeTab = ref<string>((route.query.tab as string) || 'runs');
const loadingRuns = ref(false);
const runsError = ref<string | null>(null);
const runs = ref<any[]>([]);
const applications = ref<any[]>([]);
const batteries = ref<any[]>([]);
const searchQuery = ref('');
const filterApplication = ref('');
const filterBattery = ref('');
const filterStatus = ref('');
const filterDateFrom = ref('');
const filterDateTo = ref('');
const trendFilterApplication = ref('');
const trendDays = ref(30);
const snapshots = ref<any[]>([]);
const snapshotsLoading = ref(false);
const snapshotsError = ref<string | null>(null);
const creatingSnapshot = ref(false);

const tabs = [
  { id: 'runs', label: 'Runs', icon: PlayCircle },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'trends', label: 'Trends', icon: TrendingUp },
];

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Runs & Reports' }
];

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app.name, value: app.id }))
  ];
});

const batteryOptions = computed(() => {
  return [
    { label: 'All Batteries', value: '' },
    ...batteries.value.map(battery => ({ label: battery.name, value: battery.id }))
  ];
});

const statusOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Running', value: 'running' },
];

const filteredRuns = computed(() => {
  return runs.value.filter(run => {
    const matchesSearch = !searchQuery.value || 
      run.batteryName.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      run.applicationName.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesApp = !filterApplication.value || run.applicationId === filterApplication.value;
    const matchesBattery = !filterBattery.value || run.batteryId === filterBattery.value;
    const matchesStatus = !filterStatus.value || run.status === filterStatus.value;
    const matchesDate = (!filterDateFrom.value || new Date(run.timestamp) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(run.timestamp) <= new Date(filterDateTo.value));
    return matchesSearch && matchesApp && matchesBattery && matchesStatus && matchesDate;
  });
});

const loadRuns = async () => {
  try {
    loadingRuns.value = true;
    runsError.value = null;
    const response = await axios.get('/api/v1/runs');
    runs.value = (response.data || []).map((run: any) => ({
      ...run,
      timestamp: new Date(run.timestamp || run.createdAt)
    }));
  } catch (err: any) {
    runsError.value = err.response?.data?.message || 'Failed to load runs';
    console.error('Error loading runs:', err);
  } finally {
    loadingRuns.value = false;
  }
};

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/v1/applications');
    applications.value = response.data || [];
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};

const loadBatteries = async () => {
  try {
    const response = await axios.get('/api/v1/test-batteries');
    batteries.value = response.data || [];
  } catch (err) {
    console.error('Error loading batteries:', err);
  }
};

const viewRunDetails = (runId: string) => {
  router.push(`/runs?runId=${runId}`);
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatTime = (date: Date | string | null): string => {
  if (!date) return 'Never';
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

const loadSnapshots = async () => {
  try {
    snapshotsLoading.value = true;
    snapshotsError.value = null;
    const response = await axios.get('/api/v1/compliance-snapshots', {
      params: { limit: 20 }
    });
    snapshots.value = response.data || [];
  } catch (err: any) {
    snapshotsError.value = err.response?.data?.message || 'Failed to load snapshots';
    console.error('Error loading snapshots:', err);
  } finally {
    snapshotsLoading.value = false;
  }
};

const createSnapshot = async () => {
  try {
    creatingSnapshot.value = true;
    await axios.post('/api/v1/compliance-snapshots', {
      name: `Snapshot ${new Date().toLocaleString()}`
    });
    await loadSnapshots();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create snapshot');
    console.error('Error creating snapshot:', err);
  } finally {
    creatingSnapshot.value = false;
  }
};

const viewSnapshot = (id: string) => {
  // Navigate to snapshot detail or show modal
  router.push(`/runs?snapshotId=${id}`);
};

onMounted(async () => {
  await Promise.all([loadRuns(), loadApplications(), loadBatteries()]);
  if (activeTab.value === 'reports') {
    loadSnapshots();
  }
});

watch(activeTab, (newTab) => {
  if (newTab === 'reports' && snapshots.value.length === 0) {
    loadSnapshots();
  }
});
</script>

<style scoped>
.runs-reports-page {
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
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: 1.1rem;
  color: var(--color-text-secondary);
}

.tabs-container {
  margin-bottom: 32px;
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-size: 0.95rem;
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  position: relative;
  bottom: -1px;
}

.tab-button:hover {
  color: var(--color-text-primary);
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
  background: rgba(79, 172, 254, 0.05);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  min-height: 400px;
}

.tab-panel {
  animation: fadeIn 0.3s;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-date {
  padding: 10px var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: 0.9rem;
  transition: var(--transition-all);
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown,
.filter-date {
  min-width: 150px;
}

.search-input:focus,
.filter-date:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.loading-state,
.error-state {
  text-align: center;
  padding: 80px 40px;
  color: var(--color-text-secondary);
}

.error-state {
  color: var(--color-error);
}

.runs-table-container {
  overflow-x: auto;
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.runs-table {
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
  transition: background 0.2s;
}

.run-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.harnesses-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.harness-tag {
  padding: var(--spacing-xs) 10px;
  background: var(--color-info-bg);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.status-badge {
  padding: 6px var(--spacing-md);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
  display: inline-block;
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
  color: var(--color-info);
}

.score {
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

.actions-cell {
  display: flex;
  gap: 8px;
}

.btn-link {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.btn-link:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 24px 0;
}

.trends-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.trend-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.trend-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.reports-section {
  margin-bottom: 32px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.snapshots-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.snapshot-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.snapshot-card:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.snapshot-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.snapshot-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.snapshot-score {
  font-size: 1.25rem;
  font-weight: 700;
  padding: 4px 12px;
  border-radius: 6px;
}

.score-high {
  color: #48bb78;
  background: rgba(72, 187, 120, 0.1);
}

.score-medium {
  color: #ed8936;
  background: rgba(237, 137, 54, 0.1);
}

.score-low {
  color: #f56565;
  background: rgba(245, 101, 101, 0.1);
}

.snapshot-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.empty-description {
  margin-top: 8px;
  font-size: 0.875rem;
  color: #718096;
}

.trends-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.trend-filters {
  display: flex;
  gap: 12px;
  align-items: center;
}

.filter-input {
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  width: 100px;
}

.trend-placeholder {
  text-align: center;
  padding: 60px 40px;
  color: #a0aec0;
}

.trend-note {
  font-size: 0.875rem;
  color: #718096;
  margin-top: 8px;
}

.domain-charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 24px;
  margin-top: 16px;
}

.domain-chart-item {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
}

.domain-chart-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 12px 0;
}
</style>

