<template>
  <div class="insights-runs-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Runs</h1>
          <p class="page-description">View test battery executions and results</p>
        </div>
      </div>
    </div>

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
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import axios from 'axios';
import Breadcrumb from '../../components/Breadcrumb.vue';
import Dropdown from '../../components/Dropdown.vue';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Insights & Reports', to: '/insights' },
  { label: 'Runs' }
];

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
  router.push(`/insights/runs?runId=${runId}`);
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

onMounted(async () => {
  await Promise.all([loadRuns(), loadApplications(), loadBatteries()]);
});
</script>

<style scoped>
.insights-runs-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
  margin: 0;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-date {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
}

.filter-dropdown {
  min-width: 180px;
}

.runs-table-container {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  overflow: hidden;
}

.runs-table {
  width: 100%;
  border-collapse: collapse;
}

.runs-table thead {
  background: rgba(15, 20, 25, 0.6);
}

.runs-table th {
  padding: 16px;
  text-align: left;
  font-weight: 600;
  color: #ffffff;
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.runs-table td {
  padding: 16px;
  color: #a0aec0;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
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
  gap: 4px;
}

.harness-tag {
  padding: 4px 8px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 4px;
  font-size: 0.75rem;
  color: #4facfe;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-completed {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.status-running {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.score {
  font-weight: 600;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.btn-link {
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-link:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: 60px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  color: #a0aec0;
}
</style>
