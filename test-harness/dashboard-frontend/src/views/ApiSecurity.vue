<template>
  <div class="api-security-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">API Security</h1>
          <p class="page-description">Test and monitor API security for REST and GraphQL endpoints</p>
        </div>
        <div class="header-actions">
          <button @click="showConfigModal = true" class="primary-btn">
            <Plus class="btn-icon" />
            New Configuration
          </button>
          <button @click="showEndpointModal = true" class="secondary-btn" v-if="selectedConfig">
            <Plus class="btn-icon" />
            Add Endpoint
          </button>
        </div>
      </div>
    </div>

    <!-- Config Selection -->
    <div class="config-selector" v-if="configs.length > 0">
      <label class="selector-label">Configuration:</label>
      <Dropdown
        v-model="selectedConfigId"
        :options="configOptions"
        placeholder="Select Configuration"
        class="config-dropdown"
      />
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search tests..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="loading-state">
      <p>Loading API security data...</p>
    </div>

    <!-- Test Results -->
    <div v-else-if="activeTab === 'results'" class="tab-content">
      <div class="results-grid">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="result-card"
          :class="`status-${result.status}`"
          @click="viewResultDetails(result.id)"
        >
          <div class="result-header">
            <div class="result-title-group">
              <component :is="getTestTypeIcon(result.testType)" class="result-icon" />
              <h3 class="result-title">{{ result.testName }}</h3>
            </div>
            <span class="result-status-badge" :class="`badge-${result.status}`">
              {{ result.status }}
            </span>
          </div>
          <div class="result-meta">
            <span class="meta-item">{{ result.method }} {{ result.endpoint }}</span>
            <span class="meta-item">{{ formatTestType(result.testType) }}</span>
            <span class="meta-item">{{ formatDateTime(result.timestamp) }}</span>
          </div>
          <div class="result-stats" v-if="result.statusCode || result.responseTime">
            <span v-if="result.statusCode" class="stat">
              Status: {{ result.statusCode }}
            </span>
            <span v-if="result.responseTime" class="stat">
              {{ formatDuration(result.responseTime) }}
            </span>
          </div>
          <div v-if="result.securityIssues && result.securityIssues.length > 0" class="security-issues">
            <AlertTriangle class="issue-icon" />
            <span>{{ result.securityIssues.length }} security issue(s)</span>
          </div>
        </div>
      </div>

      <div v-if="!loading && filteredResults.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No test results found</h3>
        <p>Run API security tests to see results here</p>
      </div>
    </div>

    <!-- Endpoints -->
    <div v-else-if="activeTab === 'endpoints'" class="tab-content">
      <div class="endpoints-list">
        <div
          v-for="endpoint in filteredEndpoints"
          :key="endpoint.id"
          class="endpoint-card"
        >
          <div class="endpoint-header">
            <div class="endpoint-title-group">
              <component :is="getTestTypeIcon(endpoint.apiType)" class="endpoint-icon" />
              <div>
                <h3 class="endpoint-title">{{ endpoint.name }}</h3>
                <p class="endpoint-path">{{ endpoint.method }} {{ endpoint.endpoint }}</p>
              </div>
            </div>
            <div class="endpoint-actions">
              <button @click="runTest(endpoint)" class="run-test-btn">
                <Play class="btn-icon" />
                Run Test
              </button>
              <button @click="editEndpoint(endpoint)" class="edit-btn">
                <Edit class="btn-icon" />
              </button>
              <button @click="deleteEndpoint(endpoint.id)" class="delete-btn">
                <Trash2 class="btn-icon" />
              </button>
            </div>
          </div>
          <div class="endpoint-details">
            <div class="detail-item">
              <span class="detail-label">Type:</span>
              <span class="detail-value">{{ formatTestType(endpoint.apiType) }}</span>
            </div>
            <div class="detail-item" v-if="endpoint.expectedStatus">
              <span class="detail-label">Expected Status:</span>
              <span class="detail-value">{{ endpoint.expectedStatus }}</span>
            </div>
            <div class="detail-item" v-if="endpoint.expectedAuthRequired">
              <span class="detail-label">Auth Required:</span>
              <span class="detail-value">Yes</span>
            </div>
          </div>
        </div>
      </div>

      <div v-if="!loading && filteredEndpoints.length === 0" class="empty-state">
        <Network class="empty-icon" />
        <h3>No endpoints configured</h3>
        <p>Add API endpoints to start testing</p>
      </div>
    </div>

    <!-- Configuration Modal -->
    <ConfigModal
      :show="showConfigModal"
      :config="editingConfig"
      @close="closeConfigModal"
      @save="handleConfigSave"
    />

    <!-- Endpoint Modal -->
    <EndpointModal
      :show="showEndpointModal"
      :endpoint="editingEndpoint"
      :configId="selectedConfigId"
      @close="closeEndpointModal"
      @save="handleEndpointSave"
    />

    <!-- Result Details Modal -->
    <ResultDetailsModal
      :show="showResultModal"
      :result="selectedResult"
      @close="closeResultModal"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import {
  Shield,
  Network,
  Play,
  Plus,
  Edit,
  Trash2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Lock,
  Key,
  Zap,
  Bug
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ConfigModal from '../components/ApiSecurityConfigModal.vue';
import EndpointModal from '../components/ApiSecurityEndpointModal.vue';
import ResultDetailsModal from '../components/ApiSecurityResultModal.vue';
import type {
  APISecurityTestConfigEntity,
  APIEndpointEntity,
  APISecurityTestResultEntity,
} from '../types/api-security';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'API Security' }
];

const API_BASE_URL = '/api';

const activeTab = ref<'results' | 'endpoints'>('results');
const searchQuery = ref('');
const filterType = ref('');
const filterStatus = ref('');
const selectedConfigId = ref('');
const loading = ref(true);
const showConfigModal = ref(false);
const showEndpointModal = ref(false);
const showResultModal = ref(false);
const editingConfig = ref<APISecurityTestConfigEntity | null>(null);
const editingEndpoint = ref<APIEndpointEntity | null>(null);
const selectedResult = ref<APISecurityTestResultEntity | null>(null);

const configs = ref<APISecurityTestConfigEntity[]>([]);
const endpoints = ref<APIEndpointEntity[]>([]);
const results = ref<APISecurityTestResultEntity[]>([]);

const tabs = [
  { id: 'results', label: 'Test Results', icon: Shield },
  { id: 'endpoints', label: 'Endpoints', icon: Network },
];

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'REST', value: 'rest' },
  { label: 'GraphQL', value: 'graphql' },
  { label: 'Authentication', value: 'authentication' },
  { label: 'Authorization', value: 'authorization' },
  { label: 'Rate Limiting', value: 'rate-limiting' },
  { label: 'Vulnerability', value: 'vulnerability' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Warning', value: 'warning' }
]);

const configOptions = computed(() => {
  return [
    { label: 'All Configurations', value: '' },
    ...configs.value.map(c => ({ label: c.name, value: c.id }))
  ];
});

const selectedConfig = computed(() => {
  return configs.value.find(c => c.id === selectedConfigId.value);
});

const filteredEndpoints = computed(() => {
  let filtered = endpoints.value;
  
  if (selectedConfigId.value) {
    filtered = filtered.filter(e => e.configId === selectedConfigId.value);
  }
  
  if (searchQuery.value) {
    filtered = filtered.filter(e =>
      e.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      e.endpoint.toLowerCase().includes(searchQuery.value.toLowerCase())
    );
  }
  
  if (filterType.value) {
    filtered = filtered.filter(e => e.apiType === filterType.value);
  }
  
  return filtered;
});

const filteredResults = computed(() => {
  let filtered = results.value;
  
  if (selectedConfigId.value) {
    filtered = filtered.filter(r => r.configId === selectedConfigId.value);
  }
  
  if (searchQuery.value) {
    filtered = filtered.filter(r =>
      r.testName.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      r.endpoint.toLowerCase().includes(searchQuery.value.toLowerCase())
    );
  }
  
  if (filterType.value) {
    filtered = filtered.filter(r => r.testType === filterType.value);
  }
  
  if (filterStatus.value) {
    filtered = filtered.filter(r => r.status === filterStatus.value);
  }
  
  return filtered;
});

const loadData = async () => {
  loading.value = true;
  try {
    await Promise.all([
      loadConfigs(),
      loadEndpoints(),
      loadResults(),
    ]);
  } catch (error) {
    console.error('Error loading API security data:', error);
  } finally {
    loading.value = false;
  }
};

const loadConfigs = async () => {
  try {
    const response = await fetch(`${API_BASE_URL}/api-security/configs`);
    if (response.ok) {
      const data = await response.json();
      configs.value = data.map((c: any) => ({
        ...c,
        createdAt: new Date(c.createdAt),
        updatedAt: new Date(c.updatedAt),
      }));
      
      if (configs.value.length > 0 && !selectedConfigId.value) {
        selectedConfigId.value = configs.value[0].id;
      }
    }
  } catch (error) {
    console.error('Error loading configs:', error);
  }
};

const loadEndpoints = async () => {
  try {
    const params = new URLSearchParams();
    if (selectedConfigId.value) {
      params.append('configId', selectedConfigId.value);
    }
    
    const response = await fetch(`${API_BASE_URL}/api-security/endpoints?${params.toString()}`);
    if (response.ok) {
      const data = await response.json();
      endpoints.value = data.map((e: any) => ({
        ...e,
        createdAt: new Date(e.createdAt),
        updatedAt: new Date(e.updatedAt),
      }));
    }
  } catch (error) {
    console.error('Error loading endpoints:', error);
  }
};

const loadResults = async () => {
  try {
    const params = new URLSearchParams();
    if (selectedConfigId.value) {
      params.append('configId', selectedConfigId.value);
    }
    if (filterType.value) {
      params.append('testType', filterType.value);
    }
    if (filterStatus.value) {
      params.append('status', filterStatus.value);
    }
    
    const response = await fetch(`${API_BASE_URL}/api-security/results?${params.toString()}`);
    if (response.ok) {
      const data = await response.json();
      results.value = data.map((r: any) => ({
        ...r,
        timestamp: new Date(r.timestamp),
        createdAt: new Date(r.createdAt),
        rateLimitInfo: r.rateLimitInfo ? {
          ...r.rateLimitInfo,
          resetTime: r.rateLimitInfo.resetTime ? new Date(r.rateLimitInfo.resetTime) : undefined,
        } : undefined,
      }));
    }
  } catch (error) {
    console.error('Error loading results:', error);
  }
};

const handleConfigSave = async (config: APISecurityTestConfigEntity) => {
  try {
    if (config.id) {
      // Update existing config
      const response = await fetch(`${API_BASE_URL}/api-security/configs/${config.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: config.name,
          baseUrl: config.baseUrl,
          timeout: config.timeout,
          authentication: config.authentication,
          rateLimitConfig: config.rateLimitConfig,
          headers: config.headers,
        }),
      });
      if (response.ok) {
        await loadConfigs();
        selectedConfigId.value = config.id;
      }
    } else {
      // Create new config
      const response = await fetch(`${API_BASE_URL}/api-security/configs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: config.name,
          baseUrl: config.baseUrl,
          timeout: config.timeout,
          authentication: config.authentication,
          rateLimitConfig: config.rateLimitConfig,
          headers: config.headers,
        }),
      });
      if (response.ok) {
        const newConfig = await response.json();
        await loadConfigs();
        selectedConfigId.value = newConfig.id;
      }
    }
  } catch (error) {
    console.error('Error saving config:', error);
  }
};

const handleEndpointSave = async (endpoint: APIEndpointEntity) => {
  try {
    if (endpoint.id) {
      // Update existing endpoint - Note: API doesn't have update endpoint, so we'll delete and recreate
      await deleteEndpoint(endpoint.id);
    }
    
    // Create new endpoint
    const response = await fetch(`${API_BASE_URL}/api-security/endpoints`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configId: endpoint.configId,
        name: endpoint.name,
        endpoint: endpoint.endpoint,
        method: endpoint.method,
        apiType: endpoint.apiType,
        expectedStatus: endpoint.expectedStatus,
        expectedAuthRequired: endpoint.expectedAuthRequired,
        expectedRateLimit: endpoint.expectedRateLimit,
        body: endpoint.body,
        headers: endpoint.headers,
      }),
    });
    
    if (response.ok) {
      await loadEndpoints();
    }
  } catch (error) {
    console.error('Error saving endpoint:', error);
  }
};

const runTest = async (endpoint: APIEndpointEntity) => {
  try {
    const response = await fetch(`${API_BASE_URL}/api-security/tests`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        configId: endpoint.configId,
        endpointId: endpoint.id,
        testName: endpoint.name,
        endpoint: endpoint.endpoint,
        method: endpoint.method,
        testType: endpoint.apiType,
        body: endpoint.body,
        headers: endpoint.headers,
      }),
    });

    if (response.ok) {
      await loadResults();
      activeTab.value = 'results';
    }
  } catch (error) {
    console.error('Error running test:', error);
  }
};

const editEndpoint = (endpoint: APIEndpointEntity) => {
  editingEndpoint.value = endpoint;
  showEndpointModal.value = true;
};

const deleteEndpoint = async (id: string) => {
  if (!confirm('Are you sure you want to delete this endpoint?')) return;

  try {
    const response = await fetch(`${API_BASE_URL}/api-security/endpoints/${id}`, {
      method: 'DELETE',
    });

    if (response.ok) {
      await loadEndpoints();
    }
  } catch (error) {
    console.error('Error deleting endpoint:', error);
  }
};

const viewResultDetails = async (id: string) => {
  try {
    const response = await fetch(`${API_BASE_URL}/api-security/results/${id}`);
    if (response.ok) {
      const result = await response.json();
      selectedResult.value = {
        ...result,
        timestamp: new Date(result.timestamp),
        createdAt: new Date(result.createdAt),
      };
      showResultModal.value = true;
    }
  } catch (error) {
    console.error('Error loading result details:', error);
  }
};

const closeConfigModal = () => {
  showConfigModal.value = false;
  editingConfig.value = null;
};

const closeEndpointModal = () => {
  showEndpointModal.value = false;
  editingEndpoint.value = null;
};

const closeResultModal = () => {
  showResultModal.value = false;
  selectedResult.value = null;
};

const getTestTypeIcon = (type: string) => {
  const icons: Record<string, any> = {
    'rest': Network,
    'graphql': Network,
    'authentication': Lock,
    'authorization': Key,
    'rate-limiting': Zap,
    'vulnerability': Bug
  };
  return icons[type] || Shield;
};

const formatTestType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatDateTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${ms}ms`;
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${seconds % 60}s`;
};

watch(selectedConfigId, () => {
  loadEndpoints();
  loadResults();
});

onMounted(() => {
  loadData();
});
</script>

<style scoped>
.api-security-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
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
  font-size: 1.1rem;
  color: #a0aec0;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.primary-btn,
.secondary-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border-radius: 8px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.primary-btn {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  color: #ffffff;
}

.primary-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.secondary-btn {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.secondary-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.config-selector {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.selector-label {
  font-size: 0.9rem;
  color: #a0aec0;
  font-weight: 500;
}

.config-dropdown {
  min-width: 250px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #a0aec0;
}

.tab-content {
  min-height: 400px;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 16px;
}

.result-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-left: 4px solid;
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.3s;
}

.result-card.status-passed {
  border-left-color: #22c55e;
}

.result-card.status-failed {
  border-left-color: #fc8181;
}

.result-card.status-warning {
  border-left-color: #fbbf24;
}

.result-card:hover {
  transform: translateX(4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.result-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.result-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.result-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.result-status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.badge-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.badge-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.badge-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.result-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-bottom: 12px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.meta-item {
  padding-right: 12px;
  border-right: 1px solid rgba(79, 172, 254, 0.2);
}

.meta-item:last-child {
  border-right: none;
}

.result-stats {
  display: flex;
  gap: 16px;
  margin-bottom: 12px;
  font-size: 0.875rem;
  color: #718096;
}

.security-issues {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  font-size: 0.875rem;
  color: #fc8181;
}

.issue-icon {
  width: 16px;
  height: 16px;
}

.endpoints-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.endpoint-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.endpoint-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.endpoint-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.endpoint-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.endpoint-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.endpoint-path {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  font-family: 'Courier New', monospace;
}

.endpoint-actions {
  display: flex;
  gap: 8px;
}

.run-test-btn,
.edit-btn,
.delete-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.run-test-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.edit-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.endpoint-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-item {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
}

.detail-value {
  color: #ffffff;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
}
</style>

