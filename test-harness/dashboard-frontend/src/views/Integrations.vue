<template>
  <div class="integrations-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Integrations</h1>
          <p class="page-description">Manage and monitor external tool integrations</p>
        </div>
      </div>
    </div>

    <!-- Integration List -->
    <div class="integrations-grid">
      <div
        v-for="integration in integrations"
        :key="integration.id"
        class="integration-card"
        :class="{ enabled: integration.enabled }"
      >
        <div class="integration-header">
          <div class="integration-icon-wrapper">
            <component :is="integration.icon" class="integration-icon" />
          </div>
          <div class="integration-info">
            <h3 class="integration-name">{{ integration.name }}</h3>
            <p class="integration-description">{{ integration.description }}</p>
          </div>
          <div class="integration-status">
            <span
              class="status-badge"
              :class="{
                'status-connected': integration.status === 'connected',
                'status-disconnected': integration.status === 'disconnected',
                'status-error': integration.status === 'error',
                'status-pending': integration.status === 'pending'
              }"
            >
              {{ getStatusLabel(integration.status) }}
            </span>
          </div>
        </div>

        <div class="integration-details">
          <div class="detail-row">
            <span class="detail-label">Type:</span>
            <span class="detail-value">{{ integration.type }}</span>
          </div>
          <div v-if="integration.lastRun" class="detail-row">
            <span class="detail-label">Last Run:</span>
            <span class="detail-value">{{ formatDate(integration.lastRun) }}</span>
          </div>
          <div v-if="integration.resultsCount !== undefined" class="detail-row">
            <span class="detail-label">Results:</span>
            <span class="detail-value">{{ integration.resultsCount }} tests</span>
          </div>
        </div>

        <div class="integration-actions">
          <button
            @click="configureIntegration(integration)"
            class="action-btn configure-btn"
          >
            <Settings class="action-icon" />
            Configure
          </button>
          <button
            @click="testConnection(integration)"
            class="action-btn test-btn"
            :disabled="testingConnection === integration.id"
          >
            <Plug class="action-icon" />
            {{ testingConnection === integration.id ? 'Testing...' : 'Test Connection' }}
          </button>
          <button
            @click="viewResults(integration)"
            class="action-btn results-btn"
            :disabled="!integration.enabled"
          >
            <BarChart3 class="action-icon" />
            Results
          </button>
          <button
            @click="toggleIntegration(integration)"
            class="action-btn toggle-btn"
            :class="{ enabled: integration.enabled }"
          >
            <Power class="action-icon" />
            {{ integration.enabled ? 'Disable' : 'Enable' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Integration Configuration Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="configuringIntegration" class="modal-overlay" @click="closeConfigModal">
          <div class="modal-content large-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Settings class="modal-title-icon" />
                <h2>Configure {{ configuringIntegration?.name }}</h2>
              </div>
              <button @click="closeConfigModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            
            <div class="modal-body">
              <div v-if="configuringIntegration?.id === 'sast'" class="config-form">
                <div class="form-group">
                  <label>Tool</label>
                  <select v-model="sastConfig.tool" class="form-input">
                    <option value="sonarqube">SonarQube</option>
                    <option value="checkmarx">Checkmarx</option>
                    <option value="veracode">Veracode</option>
                    <option value="snyk">Snyk</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>API Endpoint</label>
                  <input
                    v-model="sastConfig.apiEndpoint"
                    type="text"
                    placeholder="https://sonarqube.example.com/api"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>API Token</label>
                  <input
                    v-model="sastConfig.apiToken"
                    type="password"
                    placeholder="Enter API token"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Project Key</label>
                  <input
                    v-model="sastConfig.projectKey"
                    type="text"
                    placeholder="project-key"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Source Path</label>
                  <input
                    v-model="sastConfig.sourcePath"
                    type="text"
                    placeholder="/path/to/source"
                    class="form-input"
                  />
                </div>
              </div>

              <div v-if="configuringIntegration?.id === 'dast'" class="config-form">
                <div class="form-group">
                  <label>Tool</label>
                  <select v-model="dastConfig.tool" class="form-input">
                    <option value="zap">OWASP ZAP</option>
                    <option value="burp">Burp Suite</option>
                    <option value="nikto">Nikto</option>
                    <option value="nmap">Nmap</option>
                  </select>
                </div>
                <div class="form-group">
                  <label>API URL</label>
                  <input
                    v-model="dastConfig.apiUrl"
                    type="text"
                    placeholder="https://api.example.com"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Tool Endpoint</label>
                  <input
                    v-model="dastConfig.toolEndpoint"
                    type="text"
                    placeholder="https://example.com/api"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>API Key</label>
                  <input
                    v-model="dastConfig.apiKey"
                    type="password"
                    placeholder="Enter API key"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Scan Profile</label>
                  <select v-model="dastConfig.scanProfile" class="form-input">
                    <option value="quick">Quick Scan</option>
                    <option value="standard">Standard Scan</option>
                    <option value="deep">Deep Scan</option>
                  </select>
                </div>
              </div>

              <div v-if="configuringIntegration?.id === 'dbt'" class="config-form">
                <div class="form-group">
                  <label>Project Path</label>
                  <input
                    v-model="dbtConfig.projectPath"
                    type="text"
                    placeholder="/path/to/dbt/project"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Profiles Path</label>
                  <input
                    v-model="dbtConfig.profilesPath"
                    type="text"
                    placeholder="~/.dbt/profiles.yml"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Profile Name</label>
                  <input
                    v-model="dbtConfig.profileName"
                    type="text"
                    placeholder="default"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Target</label>
                  <input
                    v-model="dbtConfig.target"
                    type="text"
                    placeholder="dev"
                    class="form-input"
                  />
                </div>
              </div>

              <div v-if="configuringIntegration?.id === 'great-expectations'" class="config-form">
                <div class="form-group">
                  <label>Data Context Root Directory</label>
                  <input
                    v-model="geConfig.dataContextRootDir"
                    type="text"
                    placeholder="/path/to/great_expectations"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Suite Name</label>
                  <input
                    v-model="geConfig.suiteName"
                    type="text"
                    placeholder="default_suite"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>Expectation Suite Name</label>
                  <input
                    v-model="geConfig.expectationSuiteName"
                    type="text"
                    placeholder="my_expectation_suite"
                    class="form-input"
                  />
                </div>
              </div>

              <div class="form-actions">
                <button @click="closeConfigModal" type="button" class="btn-secondary">
                  Cancel
                </button>
                <button @click="saveConfiguration" type="button" class="btn-primary">
                  Save Configuration
                </button>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Integration Results Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="viewingResults" class="modal-overlay" @click="closeResultsModal">
          <div class="modal-content large-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <BarChart3 class="modal-title-icon" />
                <h2>{{ viewingResults?.name }} Results</h2>
              </div>
              <button @click="closeResultsModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            
            <div class="modal-body">
              <div class="results-summary">
                <div class="summary-stat">
                  <span class="stat-label">Total Tests</span>
                  <span class="stat-value">{{ integrationResults.length }}</span>
                </div>
                <div class="summary-stat">
                  <span class="stat-label">Passed</span>
                  <span class="stat-value passed">{{ passedCount }}</span>
                </div>
                <div class="summary-stat">
                  <span class="stat-label">Failed</span>
                  <span class="stat-value failed">{{ failedCount }}</span>
                </div>
                <div class="summary-stat">
                  <span class="stat-label">Last Run</span>
                  <span class="stat-value">{{ formatDate(viewingResults?.lastRun) }}</span>
                </div>
              </div>

              <div class="results-list">
                <div
                  v-for="(result, index) in integrationResults"
                  :key="index"
                  class="result-item"
                  :class="{ passed: result.passed, failed: !result.passed }"
                >
                  <div class="result-header">
                    <div class="result-status-icon">
                      <CheckCircle2 v-if="result.passed" class="icon passed" />
                      <XCircle v-else class="icon failed" />
                    </div>
                    <div class="result-info">
                      <h4 class="result-name">{{ result.testName }}</h4>
                      <span class="result-type">{{ result.testType }}</span>
                    </div>
                    <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
                  </div>
                  <div v-if="result.details" class="result-details">
                    <pre>{{ JSON.stringify(result.details, null, 2) }}</pre>
                  </div>
                  <div v-if="result.error" class="result-error">
                    <AlertTriangle class="error-icon" />
                    <span>{{ result.error }}</span>
                  </div>
                </div>
              </div>

              <div v-if="integrationResults.length === 0" class="empty-results">
                <BarChart3 class="empty-icon" />
                <p>No results available yet</p>
                <button @click="runIntegration(viewingResults)" class="btn-primary">
                  Run Integration
                </button>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  Plug,
  Settings,
  BarChart3,
  Power,
  X,
  Shield,
  Globe,
  Database,
  Activity,
  CheckCircle2,
  XCircle,
  AlertTriangle
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import { Teleport, Transition } from 'vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'Integrations' }
];

interface Integration {
  id: string;
  name: string;
  description: string;
  type: string;
  icon: any;
  enabled: boolean;
  status: 'connected' | 'disconnected' | 'error' | 'pending';
  lastRun?: Date;
  resultsCount?: number;
}

const integrations = ref<Integration[]>([
  {
    id: 'sast',
    name: 'SAST',
    description: 'Static Application Security Testing - SonarQube, Checkmarx, Veracode',
    type: 'Security',
    icon: Shield,
    enabled: false,
    status: 'disconnected',
    resultsCount: 0
  },
  {
    id: 'dast',
    name: 'DAST',
    description: 'Dynamic Application Security Testing - OWASP ZAP, Burp Suite',
    type: 'Security',
    icon: Globe,
    enabled: false,
    status: 'disconnected',
    resultsCount: 0
  },
  {
    id: 'dbt',
    name: 'DBT',
    description: 'Data Build Tool - Schema validation and data quality tests',
    type: 'Data Quality',
    icon: Database,
    enabled: false,
    status: 'disconnected',
    resultsCount: 0
  },
  {
    id: 'great-expectations',
    name: 'Great Expectations',
    description: 'Data quality validation and testing framework',
    type: 'Data Quality',
    icon: Activity,
    enabled: false,
    status: 'disconnected',
    resultsCount: 0
  }
]);

const configuringIntegration = ref<Integration | null>(null);
const viewingResults = ref<Integration | null>(null);
const testingConnection = ref<string | null>(null);
const integrationResults = ref<any[]>([]);

// Configuration state
const sastConfig = ref({
  tool: 'sonarqube',
  apiEndpoint: '',
  apiToken: '',
  projectKey: '',
  sourcePath: ''
});

const dastConfig = ref({
  tool: 'zap',
  apiUrl: '',
  toolEndpoint: '',
  apiKey: '',
  scanProfile: 'standard'
});

const dbtConfig = ref({
  projectPath: '',
  profilesPath: '',
  profileName: 'default',
  target: 'dev'
});

const geConfig = ref({
  dataContextRootDir: '',
  suiteName: 'default_suite',
  expectationSuiteName: ''
});

const passedCount = computed(() => {
  return integrationResults.value.filter(r => r.passed).length;
});

const failedCount = computed(() => {
  return integrationResults.value.filter(r => !r.passed).length;
});

const getStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    connected: 'Connected',
    disconnected: 'Not Connected',
    error: 'Error',
    pending: 'Pending'
  };
  return labels[status] || status;
};

const formatDate = (date?: Date): string => {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const formatRelativeTime = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const configureIntegration = (integration: Integration) => {
  configuringIntegration.value = integration;
  // Load existing configuration
  loadConfiguration(integration);
};

const loadConfiguration = async (integration: Integration) => {
  try {
    const response = await axios.get(`/api/integrations/${integration.id}/config`);
    const config = response.data;
    
    if (integration.id === 'sast') {
      sastConfig.value = { ...sastConfig.value, ...config };
    } else if (integration.id === 'dast') {
      dastConfig.value = { ...dastConfig.value, ...config };
    } else if (integration.id === 'dbt') {
      dbtConfig.value = { ...dbtConfig.value, ...config };
    } else if (integration.id === 'great-expectations') {
      geConfig.value = { ...geConfig.value, ...config };
    }
  } catch (error) {
    console.error('Error loading configuration:', error);
  }
};

const saveConfiguration = async () => {
  if (!configuringIntegration.value) return;
  
  try {
    let config: any = {};
    if (configuringIntegration.value.id === 'sast') {
      config = sastConfig.value;
    } else if (configuringIntegration.value.id === 'dast') {
      config = dastConfig.value;
    } else if (configuringIntegration.value.id === 'dbt') {
      config = dbtConfig.value;
    } else if (configuringIntegration.value.id === 'great-expectations') {
      config = geConfig.value;
    }
    
    await axios.post(`/api/integrations/${configuringIntegration.value.id}/config`, config);
    closeConfigModal();
    // Refresh integrations
    loadIntegrations();
  } catch (error) {
    console.error('Error saving configuration:', error);
  }
};

const closeConfigModal = () => {
  configuringIntegration.value = null;
};

const testConnection = async (integration: Integration) => {
  testingConnection.value = integration.id;
  try {
    const response = await axios.post(`/api/integrations/${integration.id}/test`);
    const result = response.data;
    
    // Update integration status
    const index = integrations.value.findIndex(i => i.id === integration.id);
    if (index !== -1) {
      integrations.value[index].status = result.connected ? 'connected' : 'error';
    }
  } catch (error) {
    console.error('Error testing connection:', error);
    const index = integrations.value.findIndex(i => i.id === integration.id);
    if (index !== -1) {
      integrations.value[index].status = 'error';
    }
  } finally {
    testingConnection.value = null;
  }
};

const toggleIntegration = async (integration: Integration) => {
  try {
    await axios.post(`/api/integrations/${integration.id}/toggle`, {
      enabled: !integration.enabled
    });
    
    const index = integrations.value.findIndex(i => i.id === integration.id);
    if (index !== -1) {
      integrations.value[index].enabled = !integrations.value[index].enabled;
    }
  } catch (error) {
    console.error('Error toggling integration:', error);
  }
};

const viewResults = async (integration: Integration) => {
  viewingResults.value = integration;
  try {
    const response = await axios.get(`/api/integrations/${integration.id}/results`);
    integrationResults.value = response.data || [];
  } catch (error) {
    console.error('Error loading results:', error);
    integrationResults.value = [];
  }
};

const closeResultsModal = () => {
  viewingResults.value = null;
  integrationResults.value = [];
};

const runIntegration = async (integration: Integration | null) => {
  if (!integration) return;
  
  try {
    await axios.post(`/api/integrations/${integration.id}/run`);
    // Reload results
    if (viewingResults.value?.id === integration.id) {
      await viewResults(integration);
    }
    // Update last run
    const index = integrations.value.findIndex(i => i.id === integration.id);
    if (index !== -1) {
      integrations.value[index].lastRun = new Date();
    }
  } catch (error) {
    console.error('Error running integration:', error);
  }
};

const loadIntegrations = async () => {
  try {
    const response = await axios.get('/api/integrations');
    const data = response.data || [];
    
    // Merge with existing integrations
    data.forEach((item: any) => {
      const index = integrations.value.findIndex(i => i.id === item.id);
      if (index !== -1) {
        integrations.value[index] = { ...integrations.value[index], ...item };
      }
    });
  } catch (error) {
    console.error('Error loading integrations:', error);
  }
};

onMounted(() => {
  loadIntegrations();
});
</script>

<style scoped>
.integrations-page {
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
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: 1.1rem;
  color: var(--color-text-secondary);
}

.integrations-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.integration-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.integration-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.integration-card.enabled {
  border-color: var(--color-success);
}

.integration-header {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.integration-icon-wrapper {
  width: 48px;
  height: 48px;
  border-radius: var(--border-radius-lg);
  background: rgba(79, 172, 254, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.integration-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.integration-info {
  flex: 1;
}

.integration-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.integration-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.integration-status {
  flex-shrink: 0;
}

.status-badge {
  padding: 6px var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-connected {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-disconnected {
  background: rgba(160, 174, 192, 0.2);
  color: var(--color-text-secondary);
}

.status-error {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-pending {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.integration-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xl);
  padding-bottom: var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: var(--font-size-sm);
}

.detail-label {
  color: var(--color-text-muted);
}

.detail-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.integration-actions {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}

.action-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 10px var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: var(--border-color-primary-active);
}

.action-btn:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.toggle-btn.enabled {
  border-color: var(--color-success);
  color: var(--color-success);
}

.toggle-btn.enabled:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  backdrop-filter: blur(4px);
  z-index: var(--z-index-modal);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.large-modal {
  max-width: 900px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.config-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-input {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: 0.9rem;
  transition: var(--transition-all);
}

.form-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-lg);
}

.btn-primary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
  border: none;
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: var(--border-color-primary-active);
}

.results-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.summary-stat {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.stat-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.stat-value.passed {
  color: #22c55e;
}

.stat-value.failed {
  color: #fc8181;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.result-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.result-item.passed {
  border-left: 4px solid #22c55e;
}

.result-item.failed {
  border-left: 4px solid #fc8181;
}

.result-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.result-status-icon {
  flex-shrink: 0;
}

.result-status-icon .icon {
  width: 20px;
  height: 20px;
}

.result-status-icon .icon.passed {
  color: #22c55e;
}

.result-status-icon .icon.failed {
  color: #fc8181;
}

.result-info {
  flex: 1;
}

.result-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.result-type {
  font-size: 0.75rem;
  color: #718096;
  text-transform: capitalize;
}

.result-time {
  font-size: 0.75rem;
  color: #718096;
}

.result-details {
  margin-top: 12px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.result-details pre {
  margin: 0;
  color: #a0aec0;
  font-size: 0.75rem;
  font-family: 'Courier New', monospace;
  white-space: pre-wrap;
  overflow-x: auto;
}

.result-error {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 12px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 6px;
  color: #fc8181;
  font-size: 0.875rem;
}

.error-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.empty-results {
  text-align: center;
  padding: 60px 40px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-results p {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 24px;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

