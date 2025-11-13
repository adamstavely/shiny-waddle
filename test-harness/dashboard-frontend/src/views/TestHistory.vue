<template>
  <div class="test-history-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test History</h1>
          <p class="page-description">View historical test execution results and track compliance over time</p>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-section">
      <div class="filter-group">
        <label>Application</label>
        <Dropdown
          v-model="filters.applicationId"
          :options="applicationOptions"
          placeholder="All Applications"
          @change="loadResults"
        />
      </div>
      <div class="filter-group">
        <label>Test Configuration</label>
        <Dropdown
          v-model="filters.testConfigurationId"
          :options="testConfigurationOptions"
          placeholder="All Configurations"
          @change="loadResults"
        />
      </div>
      <div class="filter-group">
        <label>Status</label>
        <Dropdown
          v-model="filters.status"
          :options="statusOptions"
          placeholder="All Statuses"
          @change="loadResults"
        />
      </div>
      <div class="filter-group">
        <label>Branch</label>
        <input
          v-model="filters.branch"
          type="text"
          placeholder="Filter by branch..."
          @input="debouncedLoadResults"
        />
      </div>
      <div class="filter-group">
        <label>Date Range</label>
        <div class="date-range-inputs">
          <input
            v-model="filters.startDate"
            type="date"
            @change="loadResults"
          />
          <span>to</span>
          <input
            v-model="filters.endDate"
            type="date"
            @change="loadResults"
          />
        </div>
      </div>
    </div>

    <!-- Loading/Error States -->
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading test results...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <button @click="loadResults" class="btn-retry">Retry</button>
    </div>

    <!-- Results Table -->
    <div v-else class="results-section">
      <div class="results-header">
        <div class="results-count">
          Showing {{ results.length }} of {{ totalResults }} results
        </div>
        <div class="results-pagination">
          <button
            @click="previousPage"
            :disabled="currentPage === 1"
            class="btn-secondary"
          >
            Previous
          </button>
          <span class="page-info">Page {{ currentPage }}</span>
          <button
            @click="nextPage"
            :disabled="results.length < pageSize"
            class="btn-secondary"
          >
            Next
          </button>
        </div>
      </div>

      <div class="results-table">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Application</th>
              <th>Test Configuration</th>
              <th>Status</th>
              <th>Build ID</th>
              <th>Commit</th>
              <th>Branch</th>
              <th>Duration</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="result in results" :key="result.id" class="result-row">
              <td>{{ formatDateTime(result.timestamp) }}</td>
              <td>{{ result.applicationName }}</td>
              <td>{{ result.testConfigurationName }}</td>
              <td>
                <span class="status-badge" :class="`status-${result.status}`">
                  {{ result.status }}
                </span>
              </td>
              <td>
                <span v-if="result.buildId" class="build-id">{{ truncate(result.buildId, 8) }}</span>
                <span v-else class="text-muted">-</span>
              </td>
              <td>
                <span v-if="result.commitSha" class="commit-sha">{{ truncate(result.commitSha, 7) }}</span>
                <span v-else class="text-muted">-</span>
              </td>
              <td>
                <span v-if="result.branch">{{ result.branch }}</span>
                <span v-else class="text-muted">-</span>
              </td>
              <td>
                <span v-if="result.duration">{{ formatDuration(result.duration) }}</span>
                <span v-else class="text-muted">-</span>
              </td>
              <td>
                <div class="action-buttons">
                  <button @click="viewResult(result)" class="btn-icon" title="View Details">
                    <Eye class="icon" />
                  </button>
                  <button @click="deleteResult(result.id)" class="btn-icon btn-danger" title="Delete">
                    <Trash2 class="icon" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="results.length === 0" class="empty-state">
        <History class="empty-icon" />
        <p>No test results found</p>
        <p class="empty-subtitle">Test results will appear here after tests are executed</p>
      </div>
    </div>

    <!-- Result Details Modal -->
    <TestResultModal
      v-model:isOpen="showResultModal"
      :result="selectedResult"
      @close="showResultModal = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { History, Eye, Trash2 } from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';
import TestResultModal from '../components/TestResultModal.vue';
import type { TestResult } from '../types/test-results';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test History' },
];

const loading = ref(false);
const error = ref<string | null>(null);
const results = ref<TestResult[]>([]);
const applications = ref<any[]>([]);
const testConfigurations = ref<any[]>([]);
const totalResults = ref(0);
const currentPage = ref(1);
const pageSize = 20;

const filters = ref({
  applicationId: '',
  testConfigurationId: '',
  status: '',
  branch: '',
  startDate: '',
  endDate: '',
});

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({
      label: app.name,
      value: app.id,
    })),
  ];
});

const testConfigurationOptions = computed(() => {
  return [
    { label: 'All Configurations', value: '' },
    ...testConfigurations.value.map(config => ({
      label: config.name,
      value: config.id,
    })),
  ];
});

const statusOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Partial', value: 'partial' },
  { label: 'Error', value: 'error' },
];

const showResultModal = ref(false);
const selectedResult = ref<TestResult | null>(null);

let debounceTimer: NodeJS.Timeout | null = null;

const debouncedLoadResults = () => {
  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }
  debounceTimer = setTimeout(() => {
    loadResults();
  }, 500);
};

const loadResults = async () => {
  loading.value = true;
  error.value = null;
  try {
    const params: any = {
      limit: pageSize,
      offset: (currentPage.value - 1) * pageSize,
    };

    if (filters.value.applicationId) {
      params.applicationId = filters.value.applicationId;
    }
    if (filters.value.testConfigurationId) {
      params.testConfigurationId = filters.value.testConfigurationId;
    }
    if (filters.value.status) {
      params.status = filters.value.status;
    }
    if (filters.value.branch) {
      params.branch = filters.value.branch;
    }
    if (filters.value.startDate) {
      params.startDate = filters.value.startDate;
    }
    if (filters.value.endDate) {
      params.endDate = filters.value.endDate;
    }

    const response = await axios.get('/api/test-results', { params });
    results.value = response.data.map((r: any) => ({
      ...r,
      timestamp: new Date(r.timestamp),
      createdAt: new Date(r.createdAt),
    }));
    
    // Estimate total (in a real app, this would come from the API)
    totalResults.value = results.value.length + (currentPage.value - 1) * pageSize;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test results';
    console.error('Error loading test results:', err);
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

const previousPage = () => {
  if (currentPage.value > 1) {
    currentPage.value--;
    loadResults();
  }
};

const nextPage = () => {
  if (results.value.length === pageSize) {
    currentPage.value++;
    loadResults();
  }
};

const viewResult = (result: TestResult) => {
  selectedResult.value = result;
  showResultModal.value = true;
};

const deleteResult = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test result? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-results/${id}`);
    await loadResults();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete test result';
    console.error('Error deleting test result:', err);
    alert(err.response?.data?.message || 'Failed to delete test result');
  }
};

const formatDateTime = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatDuration = (ms: number) => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
};

const truncate = (str: string, length: number) => {
  return str.length > length ? str.substring(0, length) + '...' : str;
};

// Load filters from query params
const loadFiltersFromQuery = () => {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('applicationId')) {
    filters.value.applicationId = urlParams.get('applicationId') || '';
  }
  if (urlParams.get('testConfigurationId')) {
    filters.value.testConfigurationId = urlParams.get('testConfigurationId') || '';
  }
};

onMounted(async () => {
  loadFiltersFromQuery();
  await Promise.all([loadApplications(), loadTestConfigurations(), loadResults()]);
});
</script>

<style scoped>
.test-history-page {
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
  min-width: 250px;
  flex: 1;
}

.filter-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.filter-group input {
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
}

.filter-group input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
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

.results-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.results-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.results-count {
  color: #a0aec0;
  font-size: 0.875rem;
}

.results-pagination {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.page-info {
  color: #a0aec0;
  font-size: 0.875rem;
}

.results-table {
  overflow-x: auto;
}

table {
  width: 100%;
  border-collapse: collapse;
}

thead {
  background: rgba(79, 172, 254, 0.1);
}

th {
  padding: 1rem;
  text-align: left;
  font-weight: 600;
  color: #ffffff;
  font-size: 0.875rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

td {
  padding: 1rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  color: #e2e8f0;
  font-size: 0.875rem;
}

.result-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-partial {
  background: rgba(237, 137, 54, 0.2);
  color: #ed8936;
  border: 1px solid rgba(237, 137, 54, 0.3);
}

.status-error {
  background: rgba(245, 101, 101, 0.2);
  color: #f56565;
  border: 1px solid rgba(245, 101, 101, 0.3);
}

.build-id,
.commit-sha {
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.text-muted {
  color: #718096;
  font-style: italic;
}

.action-buttons {
  display: flex;
  gap: 0.5rem;
  align-items: center;
}

.btn-icon {
  padding: 0.5rem;
  background: transparent;
  border: none;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
  color: #4facfe;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon.btn-danger {
  color: #fc8181;
}

.btn-icon.btn-danger:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
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

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
}

.btn-secondary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
</style>

