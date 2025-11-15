<template>
  <div class="test-configurations-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Configurations</h1>
          <p class="page-description">Manage test parameters and logic configurations for all test types</p>
        </div>
        <div class="header-actions">
          <button @click="showCreateModal = true" class="btn-primary">
            <Plus class="btn-icon" />
            Create Configuration
          </button>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-section">
      <div class="filter-group">
        <label>Type</label>
        <Dropdown
          v-model="filterType"
          :options="typeOptions"
          placeholder="All Types"
          @change="loadConfigurations"
        />
      </div>
      <div class="filter-group">
        <label>Search</label>
        <div class="search-input-wrapper">
          <Search class="search-icon" />
          <input
            v-model="searchQuery"
            type="text"
            placeholder="Search configurations..."
            @input="loadConfigurations"
            class="search-input"
          />
        </div>
      </div>
    </div>

    <!-- Configurations List -->
    <div v-if="loading" class="loading">Loading configurations...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else class="configurations-list">
      <div
        v-for="config in filteredConfigurations"
        :key="config.id"
        class="configuration-card"
      >
        <div class="card-header">
          <div class="card-title-section">
            <div class="card-title-row">
              <h3 class="card-title">{{ config.name }}</h3>
              <div class="config-status-badges">
                <span class="config-type-badge" :class="`type-${config.type}`">
                  {{ getTypeLabel(config.type) }}
                </span>
                <span
                  class="enabled-badge"
                  :class="config.enabled ? 'enabled' : 'disabled'"
                  :title="config.enabled ? 'Enabled' : 'Disabled'"
                >
                  {{ config.enabled ? 'Enabled' : 'Disabled' }}
                </span>
                <span
                  v-if="getLatestResult(config.id)"
                  class="test-status-badge"
                  :class="`status-${getLatestResult(config.id).status}`"
                  :title="`Last test: ${getLatestResult(config.id).status}`"
                >
                  {{ getLatestResult(config.id).status }}
                </span>
                <span
                  v-else
                  class="test-status-badge status-never"
                  title="Never tested"
                >
                  Never tested
                </span>
              </div>
            </div>
          </div>
          <div class="card-actions">
            <button 
              @click="toggleConfiguration(config)" 
              class="btn-icon" 
              :title="config.enabled ? 'Disable' : 'Enable'"
              :class="{ 'btn-warning': !config.enabled }"
            >
              <Power class="icon" />
            </button>
            <button @click="editConfiguration(config)" class="btn-icon" title="Edit">
              <Edit class="icon" />
            </button>
            <button @click="viewHistory(config.id)" class="btn-icon" title="View History">
              <History class="icon" />
            </button>
            <button @click="duplicateConfiguration(config)" class="btn-icon" title="Duplicate">
              <Copy class="icon" />
            </button>
            <button @click="testConfiguration(config)" class="btn-icon" title="Test">
              <Play class="icon" />
            </button>
            <button @click="deleteConfiguration(config.id)" class="btn-icon btn-danger" title="Delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>
        <div class="card-body">
          <p class="card-description">{{ config.description || 'No description' }}</p>
          <div class="card-meta">
            <span class="meta-item">
              <Calendar class="meta-icon" />
              Created: {{ formatDate(config.createdAt) }}
            </span>
            <span class="meta-item">
              <Calendar class="meta-icon" />
              Updated: {{ formatDate(config.updatedAt) }}
            </span>
            <span v-if="getAssignedAppsCount(config.id) > 0" class="meta-item">
              <Settings class="meta-icon" />
              Assigned to {{ getAssignedAppsCount(config.id) }} app{{ getAssignedAppsCount(config.id) !== 1 ? 's' : '' }}
            </span>
            <span v-if="getPassRate(config.id) !== null" class="meta-item">
              <span class="pass-rate-display" :class="getPassRateClass(getPassRate(config.id))">
                Pass Rate: {{ getPassRate(config.id)?.toFixed(1) }}%
              </span>
            </span>
            <span v-else class="meta-item">
              <span class="pass-rate-display pass-rate-none">No tests yet</span>
            </span>
          </div>
          <div v-if="getAssignedApps(config.id).length > 0" class="assigned-apps">
            <div
              v-for="app in getAssignedApps(config.id)"
              :key="app.id"
              class="app-badge"
            >
              {{ app.name }}
            </div>
          </div>
          <!-- Recent Tests Section -->
          <div v-if="getRecentResults(config.id).length > 0" class="recent-tests-section">
            <div class="recent-tests-header">
              <span class="recent-tests-label">Recent Tests</span>
            </div>
            <div class="recent-tests-list">
              <div
                v-for="result in getRecentResults(config.id)"
                :key="result.id"
                class="recent-test-item"
                @click="viewTestResult(result)"
              >
                <div class="recent-test-info">
                  <span class="recent-test-time">{{ formatDateTime(result.timestamp) }}</span>
                  <span class="recent-test-app">{{ result.applicationName }}</span>
                </div>
                <div class="recent-test-meta">
                  <span class="test-status-badge" :class="`status-${result.status}`">
                    {{ result.status }}
                  </span>
                  <span v-if="result.duration" class="recent-test-duration">
                    {{ formatDuration(result.duration) }}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div v-if="filteredConfigurations.length === 0" class="empty-state">
        <Settings class="empty-icon" />
        <p>No configurations found</p>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create your first configuration
        </button>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <ConfigurationModal
      :show="showCreateModal || editingConfig !== null"
      :config="editingConfig"
      :type="selectedType"
      @close="closeModal"
      @save="saveConfiguration"
    />
    
    <TestResultsModal
      :show="showResultsModal"
      :results="testResults"
      :error="testError"
      @close="closeResultsModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Plus, Edit, Trash2, Play, Copy, Calendar, Settings, Search, History, Power } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';
import ConfigurationModal from '../components/configurations/ConfigurationModal.vue';
import TestResultsModal from '../components/configurations/TestResultsModal.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Test Configurations' }
];

interface TestConfiguration {
  id: string;
  name: string;
  type: 'rls-cls' | 'network-policy' | 'dlp' | 'api-gateway' | 'distributed-systems' | 'api-security' | 'data-pipeline';
  description?: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  [key: string]: any;
}

const loading = ref(false);
const error = ref<string | null>(null);
const configurations = ref<TestConfiguration[]>([]);
const filterType = ref('');
const searchQuery = ref('');
const showCreateModal = ref(false);
const editingConfig = ref<TestConfiguration | null>(null);
const selectedType = ref<string>('');
const configApplications = ref<Record<string, any[]>>({});
const latestResults = ref<Record<string, any>>({});
const recentResults = ref<Record<string, any[]>>({});
const passRates = ref<Record<string, number>>({});

const typeOptions = [
  { label: 'All Types', value: '' },
  { label: 'RLS/CLS', value: 'rls-cls' },
  { label: 'Network Policy', value: 'network-policy' },
  { label: 'DLP', value: 'dlp' },
  { label: 'API Gateway', value: 'api-gateway' },
  { label: 'Distributed Systems', value: 'distributed-systems' },
  { label: 'API Security', value: 'api-security' },
  { label: 'Data Pipeline', value: 'data-pipeline' },
];

const filteredConfigurations = computed(() => {
  let filtered = configurations.value;

  if (filterType.value) {
    filtered = filtered.filter(c => c.type === filterType.value);
  }

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase();
    filtered = filtered.filter(c =>
      c.name.toLowerCase().includes(query) ||
      (c.description && c.description.toLowerCase().includes(query))
    );
  }

  return filtered;
});

const getTypeLabel = (type: string) => {
  const labels: Record<string, string> = {
    'rls-cls': 'RLS/CLS',
    'network-policy': 'Network Policy',
    'dlp': 'DLP',
    'api-gateway': 'API Gateway',
    'distributed-systems': 'Distributed Systems'
  };
  return labels[type] || type;
};

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString();
};

const loadConfigurations = async () => {
  loading.value = true;
  error.value = null;
  try {
    const url = filterType.value
      ? `/api/test-configurations?type=${filterType.value}`
      : '/api/test-configurations';
    const response = await axios.get(url);
    configurations.value = response.data;
    
    // Load applications for each configuration
    await loadApplicationsForConfigs();
    // Load test results for each configuration
    await loadLatestResults();
    await loadRecentResults();
    await loadPassRates();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load configurations';
    console.error('Error loading configurations:', err);
  } finally {
    loading.value = false;
  }
};

const loadApplicationsForConfigs = async () => {
  for (const config of configurations.value) {
    try {
      const response = await axios.get(`/api/test-configurations/${config.id}/applications`);
      configApplications.value[config.id] = response.data || [];
    } catch (err) {
      console.error(`Error loading applications for config ${config.id}:`, err);
      configApplications.value[config.id] = [];
    }
  }
};

const getAssignedApps = (configId: string) => {
  return configApplications.value[configId] || [];
};

const getAssignedAppsCount = (configId: string) => {
  return getAssignedApps(configId).length;
};

const loadLatestResults = async () => {
  for (const config of configurations.value) {
    try {
      const response = await axios.get(`/api/test-results/test-configuration/${config.id}?limit=1`);
      if (response.data && response.data.length > 0) {
        latestResults.value[config.id] = response.data[0];
      } else {
        latestResults.value[config.id] = null;
      }
    } catch (err) {
      console.error(`Error loading latest result for config ${config.id}:`, err);
      latestResults.value[config.id] = null;
    }
  }
};

const loadRecentResults = async () => {
  for (const config of configurations.value) {
    try {
      const response = await axios.get(`/api/test-results/test-configuration/${config.id}?limit=5`);
      recentResults.value[config.id] = response.data || [];
    } catch (err) {
      console.error(`Error loading recent results for config ${config.id}:`, err);
      recentResults.value[config.id] = [];
    }
  }
};

const loadPassRates = async () => {
  for (const config of configurations.value) {
    try {
      const response = await axios.get(`/api/test-results/compliance/metrics?testConfigurationId=${config.id}`);
      if (response.data && response.data.overall) {
        passRates.value[config.id] = response.data.overall.passRate;
      } else {
        passRates.value[config.id] = null;
      }
    } catch (err) {
      console.error(`Error loading pass rate for config ${config.id}:`, err);
      passRates.value[config.id] = null;
    }
  }
};

const getLatestResult = (configId: string) => {
  return latestResults.value[configId] || null;
};

const getRecentResults = (configId: string) => {
  return recentResults.value[configId] || [];
};

const getPassRate = (configId: string) => {
  return passRates.value[configId] ?? null;
};

const getPassRateClass = (passRate: number | null) => {
  if (passRate === null) return '';
  if (passRate >= 90) return 'pass-rate-excellent';
  if (passRate >= 70) return 'pass-rate-good';
  if (passRate >= 50) return 'pass-rate-warning';
  return 'pass-rate-poor';
};

const viewTestResult = (result: any) => {
  window.location.href = `/test-history?testConfigurationId=${result.testConfigurationId}`;
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

const editConfiguration = (config: TestConfiguration) => {
  editingConfig.value = config;
  selectedType.value = config.type;
  showCreateModal.value = true;
};

const duplicateConfiguration = async (config: TestConfiguration) => {
  try {
    const response = await axios.post(`/api/test-configurations/${config.id}/duplicate`);
    await loadConfigurations();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to duplicate configuration';
    console.error('Error duplicating configuration:', err);
  }
};

const testResults = ref<any>(null);
const testError = ref<string | null>(null);
const showResultsModal = ref(false);

const testConfiguration = async (config: TestConfiguration) => {
  loading.value = true;
  error.value = null;
  testError.value = null;
  testResults.value = null;
  try {
    const response = await axios.post(`/api/test-configurations/${config.id}/test`);
    testResults.value = response.data;
    showResultsModal.value = true;
    // Reload test results after testing
    await loadLatestResults();
    await loadRecentResults();
    await loadPassRates();
  } catch (err: any) {
    testError.value = err.response?.data?.message || 'Failed to test configuration';
    showResultsModal.value = true;
    console.error('Error testing configuration:', err);
  } finally {
    loading.value = false;
  }
};

const closeResultsModal = () => {
  showResultsModal.value = false;
  testResults.value = null;
  testError.value = null;
};

const toggleConfiguration = async (config: TestConfiguration) => {
  try {
    if (config.enabled) {
      await axios.patch(`/api/test-configurations/${config.id}/disable`);
    } else {
      await axios.patch(`/api/test-configurations/${config.id}/enable`);
    }
    await loadConfigurations();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to toggle configuration';
    console.error('Error toggling configuration:', err);
  }
};

const deleteConfiguration = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration?')) {
    return;
  }
  try {
    await axios.delete(`/api/test-configurations/${id}`);
    await loadConfigurations();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete configuration';
    console.error('Error deleting configuration:', err);
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingConfig.value = null;
  selectedType.value = '';
};

const saveConfiguration = async (configData: any) => {
  try {
    if (editingConfig.value) {
      await axios.put(`/api/test-configurations/${editingConfig.value.id}`, configData);
    } else {
      await axios.post('/api/test-configurations', configData);
    }
    await loadConfigurations();
    closeModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to save configuration';
    console.error('Error saving configuration:', err);
  }
};

onMounted(() => {
  loadConfigurations();
});
</script>

<style scoped>
.test-configurations-page {
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
  flex-wrap: wrap;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  color: #a0aec0;
  font-size: 1.1rem;
}

.header-actions {
  display: flex;
  gap: 1rem;
}

.filters-section {
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
  padding: 1.5rem;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  flex: 1;
}

.filter-group:first-child {
  min-width: 250px;
  flex: 0 0 auto;
}

.filter-group label {
  font-weight: 500;
  font-size: 0.875rem;
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
  transition: all 0.2s;
}

.filter-group select:focus,
.filter-group input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.search-input-wrapper {
  position: relative;
  display: flex;
  align-items: center;
}

.search-icon {
  position: absolute;
  left: 12px;
  width: 18px;
  height: 18px;
  color: #718096;
  pointer-events: none;
  z-index: 1;
}

.search-input-wrapper .search-input {
  padding: 0.75rem 0.75rem 0.75rem calc(1.75rem + 10px) !important;
  width: 100%;
}

.filter-group select option {
  background: #1a1f2e;
  color: #ffffff;
}

.configurations-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 1.5rem;
}

.configuration-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.3s;
}

.configuration-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
  transform: translateY(-2px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.card-title-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.config-type-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.type-rls-cls {
  background: rgba(25, 118, 210, 0.2);
  color: #64b5f6;
  border: 1px solid rgba(25, 118, 210, 0.3);
}

.type-network-policy {
  background: rgba(123, 31, 162, 0.2);
  color: #ba68c8;
  border: 1px solid rgba(123, 31, 162, 0.3);
}

.type-dlp {
  background: rgba(230, 81, 0, 0.2);
  color: #ffb74d;
  border: 1px solid rgba(230, 81, 0, 0.3);
}


.type-api-gateway {
  background: rgba(194, 24, 91, 0.2);
  color: #f48fb1;
  border: 1px solid rgba(194, 24, 91, 0.3);
}

.type-distributed-systems {
  background: rgba(0, 151, 167, 0.2);
  color: #4dd0e1;
  border: 1px solid rgba(0, 151, 167, 0.3);
}

.card-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-icon {
  padding: 0.5rem;
  border: none;
  background: transparent;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
  color: #e2e8f0;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.btn-icon.btn-danger {
  color: #e2e8f0;
}

.btn-icon.btn-danger:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.btn-icon.btn-warning {
  color: #e2e8f0;
}

.btn-icon.btn-warning:hover {
  background: rgba(237, 137, 54, 0.1);
  color: #ed8936;
}

.btn-icon.btn-warning .icon {
  color: #e2e8f0;
  stroke: #e2e8f0;
  stroke-width: 2;
}

.btn-icon.btn-warning:hover .icon {
  color: #ed8936;
  stroke: #ed8936;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
  color: #e2e8f0;
  stroke: #e2e8f0;
  stroke-width: 2;
}

.btn-icon:hover .icon {
  color: #4facfe;
  stroke: #4facfe;
}

.btn-icon.btn-danger .icon {
  color: #e2e8f0;
  stroke: #e2e8f0;
}

.btn-icon.btn-danger:hover .icon {
  color: #fc8181;
  stroke: #fc8181;
}

.card-body {
  margin-top: 1rem;
}

.card-description {
  color: #a0aec0;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
}

.card-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.875rem;
  color: #718096;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.assigned-apps {
  margin-top: 1rem;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.app-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
  font-weight: 500;
}

.test-status-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.test-status-badge.status-passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.test-status-badge.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.test-status-badge.status-partial {
  background: rgba(237, 137, 54, 0.2);
  color: #ed8936;
  border: 1px solid rgba(237, 137, 54, 0.3);
}

.test-status-badge.status-error {
  background: rgba(245, 101, 101, 0.2);
  color: #f56565;
  border: 1px solid rgba(245, 101, 101, 0.3);
}

.test-status-badge.status-never {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.enabled-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.enabled-badge.enabled {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.enabled-badge.disabled {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.pass-rate-display {
  font-size: 0.875rem;
  font-weight: 600;
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

.pass-rate-none {
  color: #a0aec0;
}

.recent-tests-section {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.recent-tests-header {
  margin-bottom: 0.75rem;
}

.recent-tests-label {
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.recent-tests-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.recent-test-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.recent-test-item:hover {
  background: rgba(79, 172, 254, 0.05);
  border-color: rgba(79, 172, 254, 0.3);
}

.recent-test-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  flex: 1;
}

.recent-test-time {
  font-size: 0.75rem;
  color: #718096;
}

.recent-test-app {
  font-size: 0.875rem;
  color: #e2e8f0;
  font-weight: 500;
}

.recent-test-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.recent-test-duration {
  font-size: 0.75rem;
  color: #a0aec0;
}

.meta-icon {
  width: 0.875rem;
  height: 0.875rem;
  color: #718096;
}

.empty-state {
  grid-column: 1 / -1;
  text-align: center;
  padding: 4rem 2rem;
  color: #a0aec0;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto 1rem;
  opacity: 0.5;
  color: #718096;
}

.loading,
.error {
  text-align: center;
  padding: 2rem;
  color: #a0aec0;
}

.error {
  color: #fc8181;
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.2s;
  font-size: 0.9rem;
  min-height: auto;
  height: auto;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 1.5rem;
  height: 1.5rem;
  flex-shrink: 0;
  display: block;
  color: inherit;
}

.btn-primary .btn-icon {
  color: #0f1419;
  width: 2rem;
  height: 2rem;
  stroke-width: 2.5;
}
</style>

