<template>
  <div class="pipelines-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Data Pipelines</h1>
          <p class="page-description">Monitor and test data pipeline compliance and security</p>
        </div>
        <button @click="showConfigModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Pipeline
        </button>
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

    <!-- Pipeline Test Results -->
    <div v-if="activeTab === 'results'" class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search pipelines..."
          class="search-input"
        />
        <Dropdown
          v-model="filterType"
          :options="typeOptions"
          placeholder="All Types"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterStage"
          :options="stageOptions"
          placeholder="All Stages"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterStatus"
          :options="statusOptions"
          placeholder="All Statuses"
          class="filter-dropdown"
        />
      </div>

      <div class="results-grid">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result.id)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.pipelineName }}</h3>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <div class="result-meta">
              <span class="result-type">{{ formatPipelineType(result.pipelineType) }}</span>
              <span class="result-stage">{{ formatStage(result.stage) }}</span>
              <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>

          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Test:</span>
              <span class="detail-value">{{ result.testName }}</span>
            </div>
            <div v-if="result.accessGranted !== undefined" class="detail-row">
              <span class="detail-label">Access:</span>
              <span class="detail-value" :class="result.accessGranted ? 'value-success' : 'value-error'">
                {{ result.accessGranted ? 'Granted' : 'Denied' }}
              </span>
            </div>
            <div v-if="result.dataValidation" class="detail-row">
              <span class="detail-label">Data Validation:</span>
              <span class="detail-value" :class="result.dataValidation.passed ? 'value-success' : 'value-error'">
                {{ result.dataValidation.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <div v-if="result.securityIssues && result.securityIssues.length > 0" class="detail-row">
              <span class="detail-label">Security Issues:</span>
              <span class="detail-value value-error">{{ result.securityIssues.length }}</span>
            </div>
            <div v-if="result.performanceMetrics" class="detail-row">
              <span class="detail-label">Duration:</span>
              <span class="detail-value">{{ formatDuration(result.performanceMetrics.executionTime) }}</span>
            </div>
          </div>

          <div v-if="result.error" class="result-error">
            <AlertTriangle class="error-icon" />
            <span>{{ result.error }}</span>
          </div>
        </div>
      </div>

      <div v-if="filteredResults.length === 0" class="empty-state">
        <Database class="empty-icon" />
        <h3>No pipeline test results found</h3>
        <p>Run pipeline tests to see results here</p>
      </div>
    </div>

    <!-- Pipeline Configurations -->
    <div v-if="activeTab === 'configurations'" class="tab-content">
      <div class="configurations-list">
        <div
          v-for="config in pipelineConfigs"
          :key="config.id"
          class="config-card"
        >
          <div class="config-header">
            <div class="config-title-row">
              <h3 class="config-name">{{ config.name }}</h3>
              <span class="config-status" :class="`status-${config.status}`">
                {{ config.status }}
              </span>
            </div>
            <div class="config-meta">
              <span class="config-type">{{ formatPipelineType(config.pipelineType) }}</span>
              <span class="config-connection">{{ config.connection?.type || 'N/A' }}</span>
            </div>
          </div>

          <div class="config-details">
            <div class="config-detail-item">
              <span class="detail-label">Source:</span>
              <span class="detail-value">{{ config.dataSource?.type || 'N/A' }}</span>
            </div>
            <div class="config-detail-item">
              <span class="detail-label">Destination:</span>
              <span class="detail-value">{{ config.dataDestination?.type || 'N/A' }}</span>
            </div>
            <div class="config-detail-item" v-if="config.lastRun">
              <span class="detail-label">Last Run:</span>
              <span class="detail-value">{{ formatRelativeTime(config.lastRun) }}</span>
            </div>
          </div>

          <div class="config-actions">
            <button @click="runPipelineTest(config.id)" class="action-btn run-btn">
              <Play class="action-icon" />
              Run Test
            </button>
            <button @click="editPipelineConfig(config.id)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="viewPipelineResults(config.id)" class="action-btn view-btn">
              <FileText class="action-icon" />
              Results
            </button>
            <button @click="deletePipelineConfig(config.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="pipelineConfigs.length === 0" class="empty-state">
        <Database class="empty-icon" />
        <h3>No pipeline configurations</h3>
        <p>Add a pipeline configuration to get started</p>
        <button @click="showConfigModal = true" class="btn-primary">
          Add Pipeline
        </button>
      </div>
    </div>

    <!-- Pipeline Configuration Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showConfigModal || editingConfig" class="modal-overlay" @click="closeConfigModal">
          <div class="modal-content large-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Database class="modal-title-icon" />
                <h2>{{ editingConfig ? 'Edit Pipeline Configuration' : 'Add Pipeline Configuration' }}</h2>
              </div>
              <button @click="closeConfigModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="savePipelineConfig" class="config-form">
                <div class="form-group">
                  <label>Pipeline Name *</label>
                  <input v-model="configForm.name" type="text" required />
                </div>

                <div class="form-row">
                  <div class="form-group">
                    <label>Pipeline Type *</label>
                    <select v-model="configForm.pipelineType" required>
                      <option value="etl">ETL</option>
                      <option value="streaming">Streaming</option>
                      <option value="batch">Batch</option>
                      <option value="real-time">Real-time</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Connection Type *</label>
                    <select v-model="configForm.connectionType" required>
                      <option value="kafka">Kafka</option>
                      <option value="spark">Spark</option>
                      <option value="airflow">Airflow</option>
                      <option value="dbt">DBT</option>
                      <option value="custom">Custom</option>
                    </select>
                  </div>
                </div>

                <div class="form-group">
                  <label>Connection Endpoint</label>
                  <input v-model="configForm.connectionEndpoint" type="text" placeholder="http://example.com:8080" />
                </div>

                <div class="form-row">
                  <div class="form-group">
                    <label>Data Source Type *</label>
                    <select v-model="configForm.dataSourceType" required>
                      <option value="database">Database</option>
                      <option value="api">API</option>
                      <option value="file">File</option>
                      <option value="stream">Stream</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Data Source Connection</label>
                    <input v-model="configForm.dataSourceConnection" type="text" placeholder="postgresql://..." />
                  </div>
                </div>

                <div class="form-row">
                  <div class="form-group">
                    <label>Data Destination Type *</label>
                    <select v-model="configForm.dataDestinationType" required>
                      <option value="database">Database</option>
                      <option value="data-warehouse">Data Warehouse</option>
                      <option value="data-lake">Data Lake</option>
                      <option value="api">API</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Data Destination Connection</label>
                    <input v-model="configForm.dataDestinationConnection" type="text" placeholder="snowflake://..." />
                  </div>
                </div>

                <div class="form-group">
                  <label>Test Stages</label>
                  <div class="checkbox-group">
                    <label class="checkbox-label">
                      <input v-model="configForm.testExtract" type="checkbox" />
                      Extract Stage
                    </label>
                    <label class="checkbox-label">
                      <input v-model="configForm.testTransform" type="checkbox" />
                      Transform Stage
                    </label>
                    <label class="checkbox-label">
                      <input v-model="configForm.testLoad" type="checkbox" />
                      Load Stage
                    </label>
                  </div>
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeConfigModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">Save Configuration</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Pipeline Result Detail Modal -->
    <TestResultDetailModal
      :show="showResultDetail"
      :result="selectedResult"
      @close="closeResultDetail"
      @export="exportPipelineResult"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  Database,
  Play,
  FileText,
  Edit,
  Plus,
  X,
  AlertTriangle,
  List,
  Settings,
  Trash2
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestResultDetailModal from '../components/TestResultDetailModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Data Pipelines' }
];

const activeTab = ref<'results' | 'configurations'>('results');
const searchQuery = ref('');
const filterType = ref('');
const filterStage = ref('');
const filterStatus = ref('');
const showConfigModal = ref(false);
const editingConfig = ref<string | null>(null);
const showResultDetail = ref(false);
const selectedResult = ref<any>(null);

const tabs = computed(() => [
  { id: 'results', label: 'Test Results', icon: FileText, badge: pipelineResults.value.length },
  { id: 'configurations', label: 'Configurations', icon: Settings, badge: pipelineConfigs.value.length }
]);

// Pipeline test results
const pipelineResults = ref([
  {
    id: '1',
    pipelineName: 'User Data ETL Pipeline',
    pipelineId: 'user-data-etl',
    pipelineType: 'etl',
    testName: 'ETL Access Control Test',
    stage: 'all',
    passed: true,
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000),
    accessGranted: true,
    dataValidation: {
      passed: true,
      completeness: 0.95,
      uniqueness: 0.98,
      validity: 0.99
    },
    securityIssues: [],
    performanceMetrics: {
      executionTime: 45000,
      throughput: 1000,
      latency: 120
    },
    error: null
  },
  {
    id: '2',
    pipelineName: 'Real-time Event Stream',
    pipelineId: 'event-stream',
    pipelineType: 'streaming',
    testName: 'Streaming Data Access Test',
    stage: 'all',
    passed: false,
    timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000),
    accessGranted: true,
    dataValidation: {
      passed: false,
      completeness: 0.85,
      uniqueness: 0.92,
      validity: 0.88
    },
    securityIssues: [
      { type: 'encryption', severity: 'high', message: 'Data not encrypted in transit' }
    ],
    performanceMetrics: {
      executionTime: 30000,
      throughput: 5000,
      latency: 50
    },
    error: null
  },
  {
    id: '3',
    pipelineName: 'Batch Data Transformation',
    pipelineId: 'batch-transform',
    pipelineType: 'batch',
    testName: 'Transformation Security Test',
    stage: 'transform',
    passed: true,
    timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000),
    accessGranted: true,
    dataValidation: {
      passed: true,
      completeness: 0.97,
      uniqueness: 0.99,
      validity: 0.98
    },
    securityIssues: [],
    performanceMetrics: {
      executionTime: 120000,
      throughput: 2000,
      latency: 200
    },
    error: null
  }
]);

// Pipeline configurations
const pipelineConfigs = ref([
  {
    id: '1',
    name: 'User Data ETL Pipeline',
    pipelineType: 'etl',
    connection: { type: 'airflow', endpoint: 'http://airflow.example.com:8080' },
    dataSource: { type: 'database', connectionString: 'postgresql://source-db:5432/mydb' },
    dataDestination: { type: 'data-warehouse', connectionString: 'snowflake://warehouse.example.com' },
    status: 'active',
    lastRun: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    id: '2',
    name: 'Real-time Event Stream',
    pipelineType: 'streaming',
    connection: { type: 'kafka', endpoint: 'kafka://kafka.example.com:9092' },
    dataSource: { type: 'stream', connectionString: 'kafka://source-topic' },
    dataDestination: { type: 'data-lake', connectionString: 's3://data-lake/events' },
    status: 'active',
    lastRun: new Date(Date.now() - 5 * 60 * 60 * 1000)
  }
]);

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'ETL', value: 'etl' },
  { label: 'Streaming', value: 'streaming' },
  { label: 'Batch', value: 'batch' },
  { label: 'Real-time', value: 'real-time' }
]);

const stageOptions = computed(() => [
  { label: 'All Stages', value: '' },
  { label: 'Extract', value: 'extract' },
  { label: 'Transform', value: 'transform' },
  { label: 'Load', value: 'load' },
  { label: 'All', value: 'all' }
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' }
]);

const filteredResults = computed(() => {
  return pipelineResults.value.filter(result => {
    const matchesSearch = result.pipelineName.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         result.testName.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || result.pipelineType === filterType.value;
    const matchesStage = !filterStage.value || result.stage === filterStage.value;
    const matchesStatus = !filterStatus.value ||
      (filterStatus.value === 'passed' && result.passed) ||
      (filterStatus.value === 'failed' && !result.passed);
    return matchesSearch && matchesType && matchesStage && matchesStatus;
  });
});

const configForm = ref({
  name: '',
  pipelineType: 'etl',
  connectionType: 'airflow',
  connectionEndpoint: '',
  dataSourceType: 'database',
  dataSourceConnection: '',
  dataDestinationType: 'data-warehouse',
  dataDestinationConnection: '',
  testExtract: true,
  testTransform: true,
  testLoad: true
});

function formatPipelineType(type: string): string {
  return type.split('-').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
}

function formatStage(stage: string): string {
  return stage.charAt(0).toUpperCase() + stage.slice(1);
}

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
}

function formatDuration(ms: number): string {
  if (!ms) return '0s';
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

function viewResultDetails(id: string) {
  const result = pipelineResults.value.find(r => r.id === id);
  if (result) {
    selectedResult.value = {
      ...result,
      testType: 'data-pipeline',
      validatorName: 'Data Pipeline Tester'
    };
    showResultDetail.value = true;
  }
}

function closeResultDetail() {
  showResultDetail.value = false;
  selectedResult.value = null;
}

function exportPipelineResult(result: any) {
  const dataStr = JSON.stringify(result, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `pipeline-result-${result.id}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function runPipelineTest(id: string) {
  const config = pipelineConfigs.value.find(c => c.id === id);
  if (config) {
    // Simulate running a test
    const newResult = {
      id: String(pipelineResults.value.length + 1),
      pipelineName: config.name,
      pipelineId: config.id,
      pipelineType: config.pipelineType,
      testName: `${config.name} Test`,
      stage: 'all',
      passed: Math.random() > 0.3,
      timestamp: new Date(),
      accessGranted: true,
      dataValidation: {
        passed: Math.random() > 0.2,
        completeness: 0.9 + Math.random() * 0.1,
        uniqueness: 0.95 + Math.random() * 0.05,
        validity: 0.95 + Math.random() * 0.05
      },
      securityIssues: [],
      performanceMetrics: {
        executionTime: 30000 + Math.random() * 60000,
        throughput: 1000 + Math.random() * 4000,
        latency: 50 + Math.random() * 150
      },
      error: null
    };
    pipelineResults.value.unshift(newResult);
    activeTab.value = 'results';
  }
}

function editPipelineConfig(id: string) {
  const config = pipelineConfigs.value.find(c => c.id === id);
  if (config) {
    editingConfig.value = id;
    configForm.value = {
      name: config.name,
      pipelineType: config.pipelineType,
      connectionType: config.connection?.type || 'airflow',
      connectionEndpoint: config.connection?.endpoint || '',
      dataSourceType: config.dataSource?.type || 'database',
      dataSourceConnection: config.dataSource?.connectionString || '',
      dataDestinationType: config.dataDestination?.type || 'data-warehouse',
      dataDestinationConnection: config.dataDestination?.connectionString || '',
      testExtract: true,
      testTransform: true,
      testLoad: true
    };
    showConfigModal.value = true;
  }
}

function viewPipelineResults(id: string) {
  activeTab.value = 'results';
  // Filter results by pipeline ID
  searchQuery.value = pipelineConfigs.value.find(c => c.id === id)?.name || '';
}

function deletePipelineConfig(id: string) {
  if (confirm('Are you sure you want to delete this pipeline configuration? This action cannot be undone.')) {
    const index = pipelineConfigs.value.findIndex(c => c.id === id);
    if (index !== -1) {
      pipelineConfigs.value.splice(index, 1);
    }
  }
}

function savePipelineConfig() {
  const configData = {
    name: configForm.value.name,
    pipelineType: configForm.value.pipelineType,
    connection: {
      type: configForm.value.connectionType,
      endpoint: configForm.value.connectionEndpoint
    },
    dataSource: {
      type: configForm.value.dataSourceType,
      connectionString: configForm.value.dataSourceConnection
    },
    dataDestination: {
      type: configForm.value.dataDestinationType,
      connectionString: configForm.value.dataDestinationConnection
    },
    status: 'active',
    lastRun: null
  };

  if (editingConfig.value) {
    const index = pipelineConfigs.value.findIndex(c => c.id === editingConfig.value);
    if (index !== -1) {
      pipelineConfigs.value[index] = {
        ...pipelineConfigs.value[index],
        ...configData
      };
    }
  } else {
    pipelineConfigs.value.push({
      id: String(pipelineConfigs.value.length + 1),
      ...configData
    });
  }
  closeConfigModal();
}

function closeConfigModal() {
  showConfigModal.value = false;
  editingConfig.value = null;
  configForm.value = {
    name: '',
    pipelineType: 'etl',
    connectionType: 'airflow',
    connectionEndpoint: '',
    dataSourceType: 'database',
    dataSourceConnection: '',
    dataDestinationType: 'data-warehouse',
    dataDestinationConnection: '',
    testExtract: true,
    testTransform: true,
    testLoad: true
  };
}
</script>

<style scoped>
.pipelines-page {
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

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
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

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-xl);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.tab-button:hover {
  color: var(--color-primary);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-badge {
  padding: 2px var(--spacing-sm);
  border-radius: 10px;
  background: var(--color-info-bg);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.tab-content {
  min-height: 400px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 10px var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: 0.9rem;
  transition: var(--transition-all);
}

.search-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-dropdown {
  min-width: 150px;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.result-card,
.config-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.result-card:hover,
.config-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.result-header,
.config-header {
  margin-bottom: var(--spacing-xl);
}

.result-title-row,
.config-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.result-name,
.config-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.result-status,
.config-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-passed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.status-active {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.result-meta,
.config-meta {
  display: flex;
  gap: var(--spacing-md);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.result-type,
.config-type {
  text-transform: capitalize;
}

.result-stage {
  padding: 2px var(--spacing-sm);
  border-radius: var(--border-radius-xs);
  background: rgba(79, 172, 254, 0.1);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.result-details,
.config-details {
  margin-bottom: var(--spacing-md);
}

.detail-row,
.config-detail-item {
  display: flex;
  justify-content: space-between;
  padding: var(--spacing-sm) 0;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.detail-row:last-child,
.config-detail-item:last-child {
  border-bottom: none;
}

.detail-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.detail-value {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.value-success {
  color: var(--color-success);
}

.value-error {
  color: var(--color-error);
}

.result-error {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-error-bg);
  border-left: 3px solid var(--color-error);
  border-radius: var(--border-radius-sm);
  color: var(--color-error);
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-md);
}

.error-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.config-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: var(--spacing-sm) var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: var(--border-color-primary-active);
}

.run-btn:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  color: var(--color-success);
}

.delete-btn {
  border-color: var(--color-error);
  color: var(--color-error);
}

.delete-btn:hover {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  color: var(--color-error);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.configurations-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.large-modal {
  max-width: 700px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
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
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #a0aec0;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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

