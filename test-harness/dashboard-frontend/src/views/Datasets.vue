<template>
  <div class="datasets-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Datasets</h1>
          <p class="page-description">Manage datasets and monitor health metrics</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Dataset
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

    <!-- Datasets Tab -->
    <div v-if="activeTab === 'datasets'" class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search datasets..."
          class="search-input"
        />
        <Dropdown
          v-model="filterType"
          :options="typeOptions"
          placeholder="All Types"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterHealth"
          :options="healthOptions"
          placeholder="All Health Statuses"
          class="filter-dropdown"
        />
      </div>

      <div class="datasets-grid">
        <div
          v-for="dataset in filteredDatasets"
          :key="dataset.id"
          class="dataset-card"
          @click="viewDatasetDetails(dataset.id)"
        >
          <div class="dataset-header">
            <div class="dataset-title-row">
              <h3 class="dataset-name">{{ dataset.name }}</h3>
              <span class="dataset-type" :class="`type-${dataset.type}`">
                {{ dataset.type }}
              </span>
            </div>
            <div class="dataset-meta">
              <span class="dataset-records">{{ formatNumber(dataset.recordCount) }} records</span>
              <span class="dataset-health" :class="`health-${dataset.healthStatus}`">
                {{ dataset.healthStatus }}
              </span>
            </div>
          </div>

          <div class="dataset-metrics">
            <div class="metric-item">
              <span class="metric-label">Privacy Score</span>
              <div class="metric-value-row">
                <span class="metric-value">{{ dataset.privacyScore || 'N/A' }}</span>
                <div class="metric-bar">
                  <div
                    class="metric-fill"
                    :style="{ width: `${dataset.privacyScore || 0}%` }"
                  ></div>
                </div>
              </div>
            </div>
            <div class="metric-item" v-if="dataset.lastTested">
              <span class="metric-label">Last Tested</span>
              <span class="metric-value">{{ formatRelativeTime(dataset.lastTested) }}</span>
            </div>
          </div>

          <div class="dataset-pii" v-if="dataset.piiFields && dataset.piiFields.length > 0">
            <span class="pii-label">PII Fields:</span>
            <div class="pii-tags">
              <span
                v-for="field in dataset.piiFields.slice(0, 3)"
                :key="field"
                class="pii-tag"
              >
                {{ field }}
              </span>
              <span v-if="dataset.piiFields.length > 3" class="more-pii">
                +{{ dataset.piiFields.length - 3 }} more
              </span>
            </div>
          </div>

          <div class="dataset-actions">
            <button @click.stop="testDataset(dataset.id)" class="action-btn test-btn">
              <Play class="action-icon" />
              Test
            </button>
            <button @click.stop="editDataset(dataset.id)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click.stop="deleteDataset(dataset.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredDatasets.length === 0" class="empty-state">
        <Database class="empty-icon" />
        <h3>No datasets found</h3>
        <p>Create your first dataset to get started</p>
        <button @click="showCreateModal = true" class="btn-primary">
          Add Dataset
        </button>
      </div>
    </div>

    <!-- Health Tests Tab -->
    <div v-if="activeTab === 'health'" class="tab-content">
      <div class="health-tests-section">
        <div class="section-header">
          <h2>Dataset Health Tests</h2>
          <button @click="runAllTests" class="btn-secondary">
            <Play class="btn-icon" />
            Run All Tests
          </button>
        </div>

        <div class="health-tests-grid">
          <div
            v-for="test in healthTests"
            :key="test.id"
            class="health-test-card"
          >
            <div class="test-header">
              <h3 class="test-name">{{ test.datasetName }}</h3>
              <span class="test-status" :class="`status-${test.status}`">
                {{ test.status }}
              </span>
            </div>
            <div class="test-results">
              <div class="result-item">
                <span class="result-label">Privacy Tests:</span>
                <span class="result-value">
                  {{ test.privacyPassed }}/{{ test.privacyTotal }} passed
                </span>
              </div>
              <div class="result-item">
                <span class="result-label">Statistical Tests:</span>
                <span class="result-value">
                  {{ test.statisticalPassed }}/{{ test.statisticalTotal }} passed
                </span>
              </div>
            </div>
            <div class="test-actions">
              <button @click="viewTestDetails(test.id)" class="btn-small">View Details</button>
              <button @click="runTest(test.id)" class="btn-small primary">Run Test</button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Modals -->
    <DatasetModal
      :show="showCreateModal || editingDataset"
      :dataset="editingDatasetData"
      @close="closeModal"
      @save="saveDataset"
    />

    <DatasetDetailModal
      :show="showDetailModal"
      :dataset="selectedDataset"
      @close="closeDetailModal"
      @test="testDataset"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import {
  Database,
  Plus,
  Edit,
  Trash2,
  Play,
  Activity
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import DatasetModal from '../components/DatasetModal.vue';
import DatasetDetailModal from '../components/DatasetDetailModal.vue';

const breadcrumbItems = [
  { label: 'Datasets', icon: Database }
];

const activeTab = ref<'datasets' | 'health'>('datasets');
const searchQuery = ref('');
const filterType = ref('');
const filterHealth = ref('');
const showCreateModal = ref(false);
const showDetailModal = ref(false);
const editingDataset = ref<string | null>(null);
const editingDatasetData = ref<any>(null);
const selectedDataset = ref<any>(null);

const tabs = computed(() => [
  { id: 'datasets', label: 'Datasets', icon: Database, badge: datasets.value.length },
  { id: 'health', label: 'Health Tests', icon: Activity, badge: healthTests.value.length }
]);

// Datasets data
const datasets = ref([
  {
    id: '1',
    name: 'masked-users',
    type: 'masked',
    recordCount: 10000,
    healthStatus: 'healthy',
    privacyScore: 85,
    lastTested: new Date(Date.now() - 2 * 60 * 60 * 1000),
    piiFields: ['email_masked', 'ssn_masked', 'phone_masked'],
    schema: {
      id: 'string',
      email_masked: 'string',
      name: 'string',
      age: 'number'
    }
  },
  {
    id: '2',
    name: 'synthetic-research-data',
    type: 'synthetic',
    recordCount: 50000,
    healthStatus: 'warning',
    privacyScore: 72,
    lastTested: new Date(Date.now() - 5 * 60 * 60 * 1000),
    piiFields: [],
    schema: {
      id: 'string',
      research_area: 'string',
      publication_count: 'number',
      citation_count: 'number'
    }
  },
  {
    id: '3',
    name: 'raw-analytics',
    type: 'raw',
    recordCount: 25000,
    healthStatus: 'critical',
    privacyScore: 45,
    lastTested: new Date(Date.now() - 24 * 60 * 60 * 1000),
    piiFields: ['email', 'user_id', 'ip_address'],
    schema: {
      id: 'string',
      email: 'string',
      user_id: 'string',
      ip_address: 'string'
    }
  }
]);

// Health tests data
const healthTests = ref([
  {
    id: '1',
    datasetName: 'masked-users',
    status: 'passed',
    privacyPassed: 3,
    privacyTotal: 3,
    statisticalPassed: 2,
    statisticalTotal: 2,
    lastRun: new Date(Date.now() - 2 * 60 * 60 * 1000)
  },
  {
    id: '2',
    datasetName: 'synthetic-research-data',
    status: 'warning',
    privacyPassed: 2,
    privacyTotal: 3,
    statisticalPassed: 1,
    statisticalTotal: 2,
    lastRun: new Date(Date.now() - 5 * 60 * 60 * 1000)
  },
  {
    id: '3',
    datasetName: 'raw-analytics',
    status: 'failed',
    privacyPassed: 1,
    privacyTotal: 3,
    statisticalPassed: 0,
    statisticalTotal: 2,
    lastRun: new Date(Date.now() - 24 * 60 * 60 * 1000)
  }
]);

const typeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Raw', value: 'raw' },
  { label: 'Masked', value: 'masked' },
  { label: 'Synthetic', value: 'synthetic' }
]);

const healthOptions = computed(() => [
  { label: 'All Health Statuses', value: '' },
  { label: 'Healthy', value: 'healthy' },
  { label: 'Warning', value: 'warning' },
  { label: 'Critical', value: 'critical' }
]);

const filteredDatasets = computed(() => {
  return datasets.value.filter(dataset => {
    const matchesSearch = dataset.name.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterType.value || dataset.type === filterType.value;
    const matchesHealth = !filterHealth.value || dataset.healthStatus === filterHealth.value;
    return matchesSearch && matchesType && matchesHealth;
  });
});

function formatNumber(num: number): string {
  return new Intl.NumberFormat().format(num);
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

function viewDatasetDetails(id: string) {
  const dataset = datasets.value.find(d => d.id === id);
  if (dataset) {
    selectedDataset.value = dataset;
    showDetailModal.value = true;
  }
}

function closeDetailModal() {
  showDetailModal.value = false;
  selectedDataset.value = null;
}

function editDataset(id: string) {
  const dataset = datasets.value.find(d => d.id === id);
  if (dataset) {
    editingDataset.value = id;
    editingDatasetData.value = dataset;
    showCreateModal.value = true;
  }
}

function deleteDataset(id: string) {
  if (confirm('Are you sure you want to delete this dataset?')) {
    const index = datasets.value.findIndex(d => d.id === id);
    if (index !== -1) {
      datasets.value.splice(index, 1);
    }
  }
}

function testDataset(id: string) {
  const dataset = datasets.value.find(d => d.id === id);
  if (dataset) {
    dataset.lastTested = new Date();
    console.log('Testing dataset:', dataset.name);
  }
}

function runAllTests() {
  console.log('Running all health tests');
}

function viewTestDetails(id: string) {
  console.log('View test details:', id);
}

function runTest(id: string) {
  console.log('Run test:', id);
}

function saveDataset(datasetData: any) {
  if (editingDataset.value) {
    const index = datasets.value.findIndex(d => d.id === editingDataset.value);
    if (index !== -1) {
      datasets.value[index] = { ...datasets.value[index], ...datasetData };
    }
  } else {
    datasets.value.push({
      id: String(datasets.value.length + 1),
      ...datasetData,
      healthStatus: 'healthy',
      privacyScore: 0,
      lastTested: null
    });
  }
  closeModal();
}

function closeModal() {
  showCreateModal.value = false;
  editingDataset.value = null;
  editingDatasetData.value = null;
}
</script>

<style scoped>
.datasets-page {
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
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
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

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
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

.tab-badge {
  padding: 2px 8px;
  border-radius: 10px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
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
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-dropdown {
  min-width: 150px;
}

.datasets-grid,
.health-tests-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.dataset-card,
.health-test-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.dataset-card:hover,
.health-test-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.dataset-header,
.test-header {
  margin-bottom: 16px;
}

.dataset-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.dataset-name,
.test-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.dataset-type {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.type-raw {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.type-masked {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.type-synthetic {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.dataset-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.dataset-records {
  font-weight: 500;
}

.dataset-health {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: capitalize;
}

.health-healthy {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.health-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.health-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.test-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.dataset-metrics {
  margin-bottom: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.metric-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-bottom: 12px;
}

.metric-item:last-child {
  margin-bottom: 0;
}

.metric-label {
  font-size: 0.75rem;
  color: #718096;
}

.metric-value-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.metric-value {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  min-width: 50px;
}

.metric-bar {
  flex: 1;
  height: 8px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 4px;
  overflow: hidden;
}

.metric-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.dataset-pii {
  margin-bottom: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.pii-label {
  font-size: 0.75rem;
  color: #718096;
  margin-bottom: 8px;
  display: block;
}

.pii-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.pii-tag {
  padding: 4px 8px;
  background: rgba(251, 191, 36, 0.2);
  border-radius: 4px;
  color: #fbbf24;
  font-size: 0.75rem;
  font-weight: 500;
}

.more-pii {
  font-size: 0.75rem;
  color: #4facfe;
  font-style: italic;
}

.dataset-actions,
.test-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
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
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.test-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.delete-btn {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.test-results {
  margin-bottom: 16px;
}

.result-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.result-item:last-child {
  border-bottom: none;
}

.result-label {
  font-size: 0.875rem;
  color: #718096;
}

.result-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.btn-small {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-small.primary {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-small.primary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.health-tests-section {
  margin-top: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
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
  margin-bottom: 24px;
}
</style>

