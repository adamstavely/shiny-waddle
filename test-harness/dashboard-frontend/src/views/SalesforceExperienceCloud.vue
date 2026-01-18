<template>
  <div class="salesforce-experience-cloud-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Salesforce Experience Cloud Testing</h1>
          <p class="page-description">Test Salesforce Experience Cloud applications for security misconfigurations using aura-inspector</p>
        </div>
        <div class="header-actions">
          <button @click="showConfigModal = true" class="btn-secondary">
            <Plus class="btn-icon" />
            New Configuration
          </button>
          <button @click="showTestModal = true" class="btn-primary" :disabled="configs.length === 0">
            <Play class="btn-icon" />
            Run Test
          </button>
        </div>
      </div>
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
        <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
      </button>
    </div>

    <!-- Configurations Tab -->
    <div v-if="activeTab === 'configs'" class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search configurations..."
          class="search-input"
        />
      </div>

      <div v-if="loading" class="loading-state">
        <Loader2 class="loading-icon spin" />
        <p>Loading configurations...</p>
      </div>

      <div v-else-if="filteredConfigs.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No configurations found</h3>
        <p>Create a configuration to start testing Salesforce Experience Cloud applications</p>
        <button @click="showConfigModal = true" class="btn-primary">
          Create Configuration
        </button>
      </div>

      <div v-else class="configs-grid">
        <div
          v-for="config in filteredConfigs"
          :key="config.id"
          class="config-card"
          @click="viewConfig(config)"
        >
          <div class="config-header">
            <div class="config-title-row">
              <h3 class="config-name">{{ config.name }}</h3>
              <button
                @click.stop="deleteConfig(config.id)"
                class="delete-btn"
                title="Delete configuration"
              >
                <Trash2 class="delete-icon" />
              </button>
            </div>
            <div class="config-meta">
              <span class="config-url">{{ config.url }}</span>
              <span class="config-time">{{ formatRelativeTime(new Date(config.updatedAt)) }}</span>
            </div>
          </div>

          <div class="config-details">
            <div v-if="config.app" class="detail-row">
              <span class="detail-label">App:</span>
              <span class="detail-value">{{ config.app }}</span>
            </div>
            <div v-if="config.objectList && config.objectList.length > 0" class="detail-row">
              <span class="detail-label">Objects:</span>
              <span class="detail-value">{{ config.objectList.join(', ') }}</span>
            </div>
            <div v-if="config.cookies" class="detail-row">
              <span class="detail-label">Authentication:</span>
              <span class="detail-value">Configured</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Results Tab -->
    <div v-if="activeTab === 'results'" class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search results..."
          class="search-input"
        />
        <select v-model="filterStatus" class="filter-select">
          <option value="">All Statuses</option>
          <option value="passed">Passed</option>
          <option value="failed">Failed</option>
          <option value="warning">Warning</option>
        </select>
        <select v-model="filterTestType" class="filter-select">
          <option value="">All Test Types</option>
          <option value="guest-access">Guest Access</option>
          <option value="authenticated-access">Authenticated Access</option>
          <option value="graphql">GraphQL</option>
          <option value="self-registration">Self-Registration</option>
          <option value="record-lists">Record Lists</option>
          <option value="home-urls">Home URLs</option>
          <option value="object-access">Object Access</option>
          <option value="full-audit">Full Audit</option>
        </select>
      </div>

      <div v-if="loadingResults" class="loading-state">
        <Loader2 class="loading-icon spin" />
        <p>Loading results...</p>
      </div>

      <div v-else-if="filteredResults.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No test results found</h3>
        <p>Run tests to see results here</p>
      </div>

      <div v-else class="results-grid">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.testName }}</h3>
              <span class="result-status" :class="`status-${result.status}`">
                {{ result.status }}
              </span>
            </div>
            <div class="result-meta">
              <span class="result-type">{{ formatTestType(result.testType) }}</span>
              <span class="result-time">{{ formatRelativeTime(new Date(result.timestamp)) }}</span>
            </div>
          </div>

          <div v-if="result.summary" class="result-details">
            <div class="detail-row">
              <span class="detail-label">Total Findings:</span>
              <span class="detail-value">{{ result.summary.totalFindings }}</span>
            </div>
            <div v-if="result.summary.criticalCount > 0" class="detail-row">
              <span class="detail-label">Critical:</span>
              <span class="detail-value value-error">{{ result.summary.criticalCount }}</span>
            </div>
            <div v-if="result.summary.highCount > 0" class="detail-row">
              <span class="detail-label">High:</span>
              <span class="detail-value value-warning">{{ result.summary.highCount }}</span>
            </div>
          </div>

          <div v-if="result.error" class="result-error">
            <AlertCircle class="error-icon" />
            <span>{{ result.error }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Configuration Modal -->
    <SalesforceExperienceCloudConfigModal
      :show="showConfigModal"
      :config="selectedConfig"
      @close="closeConfigModal"
      @save="handleConfigSave"
    />

    <!-- Test Runner Modal -->
    <SalesforceExperienceCloudTestRunner
      :show="showTestModal"
      :configs="configs"
      @close="closeTestModal"
      @test-complete="handleTestComplete"
    />

    <!-- Result Detail Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showDetailModal && selectedResult" class="modal-overlay" @click="closeDetailModal">
          <div class="modal-content large" @click.stop>
            <div class="modal-header">
              <h2>Test Result Details</h2>
              <button @click="closeDetailModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="detail-section">
                <h3>Summary</h3>
                <div class="detail-grid">
                  <div class="detail-item">
                    <span class="detail-label">Status:</span>
                    <span :class="`value-${selectedResult.status}`">
                      {{ selectedResult.status }}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Test Type:</span>
                    <span>{{ formatTestType(selectedResult.testType) }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Timestamp:</span>
                    <span>{{ formatDate(new Date(selectedResult.timestamp)) }}</span>
                  </div>
                  <div v-if="selectedResult.summary" class="detail-item">
                    <span class="detail-label">Total Findings:</span>
                    <span>{{ selectedResult.summary.totalFindings }}</span>
                  </div>
                </div>
              </div>

              <div v-if="selectedResult.findings && selectedResult.findings.length > 0" class="detail-section">
                <h3>Findings</h3>
                <div class="findings-list">
                  <div
                    v-for="(finding, index) in selectedResult.findings"
                    :key="index"
                    class="finding-item"
                    :class="`finding-${finding.severity}`"
                  >
                    <div class="finding-header">
                      <span class="finding-severity">{{ finding.severity }}</span>
                      <span class="finding-type">{{ finding.type }}</span>
                    </div>
                    <p class="finding-description">{{ finding.description }}</p>
                    <div v-if="finding.objects && finding.objects.length > 0" class="finding-details">
                      <strong>Objects:</strong> {{ finding.objects.join(', ') }}
                    </div>
                    <div v-if="finding.urls && finding.urls.length > 0" class="finding-details">
                      <strong>URLs:</strong> {{ finding.urls.join(', ') }}
                    </div>
                  </div>
                </div>
              </div>

              <div v-if="selectedResult.error" class="detail-section">
                <h3>Error</h3>
                <div class="error-box">
                  <AlertCircle class="error-icon" />
                  <pre>{{ selectedResult.error }}</pre>
                </div>
              </div>

              <div v-if="selectedResult.details" class="detail-section">
                <h3>Details</h3>
                <pre class="details-json">{{ JSON.stringify(selectedResult.details, null, 2) }}</pre>
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
import axios from 'axios';
import {
  Shield,
  FileText,
  Play,
  Plus,
  Trash2,
  X,
  Loader2,
  AlertCircle,
  Settings,
  ListChecks,
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import SalesforceExperienceCloudConfigModal from '../components/SalesforceExperienceCloudConfigModal.vue';
import SalesforceExperienceCloudTestRunner from '../components/SalesforceExperienceCloudTestRunner.vue';
import type {
  SalesforceExperienceCloudConfigEntity,
  SalesforceExperienceCloudTestResultEntity,
} from '../types/salesforce-experience-cloud';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
];

const activeTab = ref<'configs' | 'results'>('configs');
const searchQuery = ref('');
const filterStatus = ref('');
const filterTestType = ref('');
const loading = ref(false);
const loadingResults = ref(false);
const showConfigModal = ref(false);
const showTestModal = ref(false);
const showDetailModal = ref(false);
const selectedConfig = ref<SalesforceExperienceCloudConfigEntity | null>(null);
const selectedResult = ref<SalesforceExperienceCloudTestResultEntity | null>(null);

const configs = ref<SalesforceExperienceCloudConfigEntity[]>([]);
const results = ref<SalesforceExperienceCloudTestResultEntity[]>([]);

const tabs = [
  { id: 'configs', label: 'Configurations', icon: Settings, badge: configs.value.length },
  { id: 'results', label: 'Test Results', icon: ListChecks, badge: results.value.length },
];

const filteredConfigs = computed(() => {
  let filtered = configs.value;
  if (searchQuery.value) {
    filtered = filtered.filter(c =>
      c.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      c.url.toLowerCase().includes(searchQuery.value.toLowerCase())
    );
  }
  return filtered;
});

const filteredResults = computed(() => {
  let filtered = results.value;
  if (searchQuery.value) {
    filtered = filtered.filter(r =>
      r.testName.toLowerCase().includes(searchQuery.value.toLowerCase())
    );
  }
  if (filterStatus.value) {
    filtered = filtered.filter(r => r.status === filterStatus.value);
  }
  if (filterTestType.value) {
    filtered = filtered.filter(r => r.testType === filterTestType.value);
  }
  return filtered;
});

const loadConfigs = async () => {
  loading.value = true;
  try {
    const response = await axios.get('/api/salesforce-experience-cloud/configs');
    configs.value = response.data;
  } catch (error: any) {
    console.error('Error loading configs:', error);
    alert('Failed to load configurations');
  } finally {
    loading.value = false;
  }
};

const loadResults = async () => {
  loadingResults.value = true;
  try {
    const response = await axios.get('/api/salesforce-experience-cloud/results');
    results.value = response.data;
  } catch (error: any) {
    console.error('Error loading results:', error);
    alert('Failed to load test results');
  } finally {
    loadingResults.value = false;
  }
};

const viewConfig = (config: SalesforceExperienceCloudConfigEntity) => {
  selectedConfig.value = config;
  showConfigModal.value = true;
};

const deleteConfig = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration?')) {
    return;
  }
  try {
    await axios.delete(`/api/salesforce-experience-cloud/configs/${id}`);
    await loadConfigs();
    await loadResults(); // Results may be deleted too
  } catch (error: any) {
    console.error('Error deleting config:', error);
    alert('Failed to delete configuration');
  }
};

const handleConfigSave = async () => {
  await loadConfigs();
  closeConfigModal();
};

const handleTestComplete = async () => {
  await loadResults();
  activeTab.value = 'results';
  closeTestModal();
};

const viewResultDetails = (result: SalesforceExperienceCloudTestResultEntity) => {
  selectedResult.value = result;
  showDetailModal.value = true;
};

const closeConfigModal = () => {
  showConfigModal.value = false;
  selectedConfig.value = null;
};

const closeTestModal = () => {
  showTestModal.value = false;
};

const closeDetailModal = () => {
  showDetailModal.value = false;
  selectedResult.value = null;
};

const formatTestType = (type: string) => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatRelativeTime = (date: Date) => {
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (days > 0) return `${days}d ago`;
  if (hours > 0) return `${hours}h ago`;
  if (minutes > 0) return `${minutes}m ago`;
  return 'Just now';
};

const formatDate = (date: Date) => {
  return new Intl.DateTimeFormat('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
};

onMounted(async () => {
  await Promise.all([loadConfigs(), loadResults()]);
});
</script>

<style scoped>
.salesforce-experience-cloud-page {
  padding: 24px;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 24px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.page-title {
  font-size: 28px;
  font-weight: 600;
  margin: 0 0 8px 0;
  color: var(--text-primary);
}

.page-description {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0;
}

.tabs {
  display: flex;
  gap: 8px;
  border-bottom: 2px solid var(--border-color);
  margin-bottom: 24px;
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: none;
  border: none;
  border-bottom: 2px solid transparent;
  cursor: pointer;
  font-size: 14px;
  font-weight: 500;
  color: var(--text-secondary);
  transition: all 0.2s;
  margin-bottom: -2px;
}

.tab-button:hover {
  color: var(--text-primary);
}

.tab-button.active {
  color: var(--primary-color);
  border-bottom-color: var(--primary-color);
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.tab-badge {
  background: var(--primary-color);
  color: white;
  padding: 2px 6px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.search-input,
.filter-select {
  padding: 8px 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
}

.search-input {
  flex: 1;
  max-width: 400px;
}

.configs-grid,
.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 16px;
}

.config-card,
.result-card {
  background: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.config-card:hover,
.result-card:hover {
  border-color: var(--primary-color);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.config-header,
.result-header {
  margin-bottom: 12px;
}

.config-title-row,
.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.config-name,
.result-name {
  font-size: 16px;
  font-weight: 600;
  margin: 0;
  color: var(--text-primary);
}

.delete-btn {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  color: var(--text-secondary);
  transition: color 0.2s;
}

.delete-btn:hover {
  color: var(--error-color);
}

.delete-icon {
  width: 16px;
  height: 16px;
}

.config-meta,
.result-meta {
  display: flex;
  gap: 12px;
  font-size: 12px;
  color: var(--text-secondary);
}

.config-url {
  font-family: monospace;
}

.result-status {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}

.status-passed {
  background: var(--success-bg);
  color: var(--success-color);
}

.status-failed {
  background: var(--error-bg);
  color: var(--error-color);
}

.status-warning {
  background: var(--warning-bg);
  color: var(--warning-color);
}

.config-details,
.result-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  font-size: 13px;
}

.detail-label {
  color: var(--text-secondary);
}

.detail-value {
  color: var(--text-primary);
  font-weight: 500;
}

.value-error {
  color: var(--error-color);
}

.value-warning {
  color: var(--warning-color);
}

.value-success {
  color: var(--success-color);
}

.result-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  background: var(--error-bg);
  color: var(--error-color);
  border-radius: 4px;
  font-size: 13px;
  margin-top: 12px;
}

.error-icon {
  width: 16px;
  height: 16px;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 20px;
  text-align: center;
}

.loading-icon {
  width: 48px;
  height: 48px;
  color: var(--primary-color);
  margin-bottom: 16px;
}

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--text-tertiary);
  margin-bottom: 16px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: var(--card-bg);
  border-radius: 8px;
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-content.large {
  max-width: 900px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid var(--border-color);
}

.modal-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  color: var(--text-secondary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 20px;
}

.detail-section {
  margin-bottom: 24px;
}

.detail-section h3 {
  font-size: 16px;
  font-weight: 600;
  margin: 0 0 12px 0;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  padding: 8px;
  background: var(--bg-secondary);
  border-radius: 4px;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.finding-item {
  padding: 12px;
  border-radius: 6px;
  border-left: 4px solid;
}

.finding-critical {
  background: var(--error-bg);
  border-left-color: var(--error-color);
}

.finding-high {
  background: var(--warning-bg);
  border-left-color: var(--warning-color);
}

.finding-medium {
  background: var(--info-bg);
  border-left-color: var(--info-color);
}

.finding-low,
.finding-info {
  background: var(--bg-secondary);
  border-left-color: var(--text-tertiary);
}

.finding-header {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
}

.finding-severity {
  text-transform: uppercase;
  font-weight: 600;
  font-size: 12px;
}

.finding-type {
  font-size: 12px;
  color: var(--text-secondary);
}

.finding-description {
  margin: 0 0 8px 0;
  font-size: 14px;
}

.finding-details {
  font-size: 12px;
  color: var(--text-secondary);
}

.error-box {
  padding: 12px;
  background: var(--error-bg);
  border-radius: 6px;
  display: flex;
  gap: 8px;
}

.error-box pre {
  margin: 0;
  font-size: 12px;
  color: var(--error-color);
  white-space: pre-wrap;
}

.details-json {
  background: var(--bg-secondary);
  padding: 12px;
  border-radius: 6px;
  font-size: 12px;
  overflow-x: auto;
  max-height: 400px;
  overflow-y: auto;
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: var(--primary-color);
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: var(--primary-color-dark);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
}

.btn-secondary:hover {
  background: var(--bg-tertiary);
}

.btn-icon {
  width: 16px;
  height: 16px;
}
</style>
