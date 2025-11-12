<template>
  <div class="distributed-systems-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Distributed Systems</h1>
          <p class="page-description">Test and monitor compliance across multi-region deployments</p>
        </div>
        <div class="header-actions">
          <button @click="navigateToConfig" class="btn-secondary">
            <Settings class="btn-icon" />
            Configure
          </button>
          <button @click="showTestModal = true" class="btn-primary">
            <Play class="btn-icon" />
            Run Test
          </button>
        </div>
      </div>
    </div>

    <!-- Configuration Selector -->
    <div class="config-selector">
      <div class="selector-group">
        <label>Use Configuration:</label>
        <select v-model="selectedConfigId" @change="loadConfiguration">
          <option value="">None (Use Defaults)</option>
          <option v-for="config in configurations" :key="config.id" :value="config.id">
            {{ config.name }}
          </option>
        </select>
      </div>
      <div class="selector-actions">
        <button @click="saveCurrentAsConfig" class="btn-secondary" :disabled="!hasTestData">
          <Save class="btn-icon" />
          Save as Configuration
        </button>
      </div>
      <div v-if="selectedConfigId" class="active-config">
        <CheckCircle2 class="icon" />
        <span>Using: {{ getConfigName(selectedConfigId) }}</span>
      </div>
    </div>

    <!-- Test Results -->
    <div class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search tests..."
          class="search-input"
        />
        <Dropdown
          v-model="filterTestType"
          :options="testTypeOptions"
          placeholder="All Test Types"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterRegion"
          :options="regionOptions"
          placeholder="All Regions"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterStatus"
          :options="statusOptions"
          placeholder="All Statuses"
          class="filter-dropdown"
        />
      </div>

      <!-- Test Results List -->
      <div class="test-results-list">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="test-result-card"
          @click="viewTestResult(result.id)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.testName }}</h3>
              <span class="result-status" :class="`status-${result.passed ? 'passed' : 'failed'}`">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <p class="result-meta">
              {{ formatTestType(result.distributedTestType) }} • {{ formatDate(result.timestamp) }}
            </p>
          </div>

          <div class="result-summary">
            <div class="summary-item">
              <Globe class="summary-icon" />
              <span>{{ result.regionResults?.length || 0 }} regions</span>
            </div>
            <div class="summary-item" v-if="result.consistencyCheck">
              <CheckCircle2 v-if="result.consistencyCheck.consistent" class="summary-icon passed" />
              <X v-else class="summary-icon failed" />
              <span>{{ result.consistencyCheck.consistent ? 'Consistent' : 'Inconsistent' }}</span>
            </div>
            <div class="summary-item" v-if="result.performanceMetrics">
              <Clock class="summary-icon" />
              <span>{{ result.performanceMetrics.averageLatency }}ms avg</span>
            </div>
          </div>

          <!-- Region Results Preview -->
          <div v-if="result.regionResults && result.regionResults.length > 0" class="region-preview">
            <div
              v-for="region in result.regionResults.slice(0, 3)"
              :key="region.regionId"
              class="region-badge"
              :class="{ 'allowed': region.allowed, 'denied': !region.allowed }"
            >
              <Globe class="region-icon" />
              <span>{{ region.regionName }}</span>
              <CheckCircle2 v-if="region.allowed" class="region-status-icon" />
              <X v-else class="region-status-icon" />
            </div>
            <div v-if="result.regionResults.length > 3" class="region-more">
              +{{ result.regionResults.length - 3 }} more
            </div>
          </div>

          <!-- Inconsistencies Alert -->
          <div
            v-if="result.consistencyCheck && !result.consistencyCheck.consistent && result.consistencyCheck.inconsistencies.length > 0"
            class="inconsistencies-alert"
          >
            <AlertTriangle class="alert-icon" />
            <span>{{ result.consistencyCheck.inconsistencies.length }} inconsistency(ies) detected</span>
          </div>

          <div class="result-actions">
            <button @click.stop="viewTestResult(result.id)" class="action-btn view-btn">
              <Eye class="action-icon" />
              View Details
            </button>
            <button @click.stop="deleteTestResult(result.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredResults.length === 0 && !isLoading" class="empty-state">
        <Globe class="empty-icon" />
        <h3>No test results found</h3>
        <p>Run a distributed systems test to get started</p>
        <button @click="showTestModal = true" class="btn-primary">
          Run Test
        </button>
      </div>
    </div>


    <!-- Test Execution Modal -->
    <DistributedTestModal
      v-model:isOpen="showTestModal"
      :regions="regionsFromConfig"
      :configId="selectedConfigId"
      @test-executed="handleTestExecuted"
    />

    <!-- Test Result Detail Modal -->
    <TestResultModal
      v-model:isOpen="showResultModal"
      :result="selectedResult"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  Globe,
  Settings,
  Play,
  CheckCircle2,
  X,
  Eye,
  Trash2,
  Clock,
  AlertTriangle,
  Save
} from 'lucide-vue-next';
import { useRouter } from 'vue-router';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import DistributedTestModal from '../components/DistributedTestModal.vue';
import TestResultModal from '../components/TestResultModal.vue';

const router = useRouter();
const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Distributed Systems' }
];

const searchQuery = ref('');
const filterTestType = ref('');
const filterRegion = ref('');
const filterStatus = ref('');
const isLoading = ref(false);
const showTestModal = ref(false);
const showResultModal = ref(false);
const selectedResult = ref<any>(null);

const testResults = ref<any[]>([]);
const selectedConfigId = ref<string>('');
const configurations = ref<any[]>([]);
const regionsFromConfig = ref<any[]>([]);

const testTypeOptions = computed(() => [
  { label: 'All Test Types', value: '' },
  { label: 'Policy Consistency', value: 'policy-consistency' },
  { label: 'Multi-Region', value: 'multi-region' },
  { label: 'Synchronization', value: 'synchronization' },
  { label: 'Transaction', value: 'transaction' },
  { label: 'Eventual Consistency', value: 'eventual-consistency' },
]);

const regionOptions = computed(() => [
  { label: 'All Regions', value: '' },
  ...regionsFromConfig.value.map(r => ({ label: r.name, value: r.id })),
]);

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' },
]);

const hasTestData = computed(() => {
  return regionsFromConfig.value.length > 0;
});

const getConfigName = (id: string) => {
  const config = configurations.value.find(c => c.id === id);
  return config?.name || id;
};

const filteredResults = computed(() => {
  return testResults.value.filter(result => {
    const matchesSearch = result.testName?.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesType = !filterTestType.value || result.distributedTestType === filterTestType.value;
    const matchesRegion = !filterRegion.value || 
      result.regionResults?.some((r: any) => r.regionId === filterRegion.value);
    const matchesStatus = !filterStatus.value || 
      (filterStatus.value === 'passed' && result.passed) ||
      (filterStatus.value === 'failed' && !result.passed);
    return matchesSearch && matchesType && matchesRegion && matchesStatus;
  });
});

const formatTestType = (type: string): string => {
  return type
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};

const loadTestResults = async () => {
  isLoading.value = true;
  try {
    const response = await axios.get('/api/distributed-systems/tests');
    testResults.value = response.data.map((r: any) => ({
      ...r,
      timestamp: new Date(r.timestamp),
    }));
  } catch (error) {
    console.error('Failed to load test results:', error);
  } finally {
    isLoading.value = false;
  }
};

const loadConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations?type=distributed-systems');
    configurations.value = response.data;
  } catch (error) {
    console.error('Error loading configurations:', error);
  }
};

const loadConfiguration = async () => {
  if (!selectedConfigId.value) {
    regionsFromConfig.value = [];
    return;
  }
  try {
    const response = await axios.get(`/api/test-configurations/${selectedConfigId.value}`);
    const config = response.data;
    if (config.regions) {
      regionsFromConfig.value = config.regions;
    } else {
      regionsFromConfig.value = [];
    }
  } catch (error) {
    console.error('Error loading configuration:', error);
    regionsFromConfig.value = [];
  }
};

const saveCurrentAsConfig = async () => {
  if (regionsFromConfig.value.length === 0) {
    alert('No regions configured. Please configure regions in the test configuration first.');
    return;
  }
  const name = prompt('Enter configuration name:');
  if (!name) return;
  try {
    await axios.post('/api/test-configurations', {
      name,
      type: 'distributed-systems',
      regions: regionsFromConfig.value,
    });
    await loadConfigurations();
    alert('Configuration saved successfully!');
  } catch (error: any) {
    alert('Error saving configuration: ' + (error.response?.data?.message || error.message));
  }
};

const navigateToConfig = () => {
  router.push('/test-configurations');
};

const viewTestResult = async (id: string) => {
  try {
    const response = await axios.get(`/api/distributed-systems/tests/${id}`);
    selectedResult.value = {
      ...response.data,
      timestamp: new Date(response.data.timestamp),
    };
    showResultModal.value = true;
  } catch (error) {
    console.error('Failed to load test result:', error);
  }
};

const deleteTestResult = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test result?')) return;
  try {
    await axios.delete(`/api/distributed-systems/tests/${id}`);
    await loadTestResults();
  } catch (error) {
    console.error('Failed to delete test result:', error);
    alert('Failed to delete test result. Please try again.');
  }
};

const handleTestExecuted = async () => {
  await loadTestResults();
};

onMounted(async () => {
  await Promise.all([loadTestResults(), loadConfigurations()]);
});
</script>

<style scoped>
.distributed-systems-page {
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

.header-actions {
  display: flex;
  gap: 12px;
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

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
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
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.config-selector {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 24px;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
}

.selector-group {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.selector-group label {
  color: #a0aec0;
  font-weight: 500;
  font-size: 0.9rem;
}

.selector-group select {
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.9rem;
  min-width: 200px;
}

.selector-group select:focus {
  outline: none;
  border-color: #4facfe;
}

.selector-actions {
  margin-left: auto;
}

.active-config {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 8px 12px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  color: #22c55e;
  font-size: 0.875rem;
  font-weight: 500;
}

.active-config .icon {
  width: 16px;
  height: 16px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-dropdown {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.test-results-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.test-result-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.test-result-card:hover {
  transform: translateY(-2px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.result-header {
  margin-bottom: 16px;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.result-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.result-status {
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

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.result-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.result-summary {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.summary-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.summary-icon {
  width: 16px;
  height: 16px;
}

.summary-icon.passed {
  color: #22c55e;
}

.summary-icon.failed {
  color: #fc8181;
}

.region-preview {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.region-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 0.875rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.region-badge.allowed {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.region-badge.denied {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.region-icon {
  width: 14px;
  height: 14px;
}

.region-status-icon {
  width: 14px;
  height: 14px;
}

.region-more {
  padding: 6px 12px;
  font-size: 0.875rem;
  color: #718096;
}

.inconsistencies-alert {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  color: #fbbf24;
  font-size: 0.875rem;
  margin-bottom: 16px;
}

.alert-icon {
  width: 16px;
  height: 16px;
}

.result-actions {
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
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.view-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
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

.config-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
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

.regions-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.region-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.region-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 16px;
}

.region-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.region-id {
  font-size: 0.875rem;
  color: #718096;
  margin: 0;
}

.region-actions {
  display: flex;
  gap: 8px;
}

.icon-btn {
  padding: 8px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.icon-btn.delete:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.4);
  color: #fc8181;
}

.icon {
  width: 16px;
  height: 16px;
}

.region-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.detail-item {
  display: flex;
  gap: 8px;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
  min-width: 120px;
}

.detail-value {
  font-size: 0.875rem;
  color: #ffffff;
}

.sync-config {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #ffffff;
  font-size: 0.9rem;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.sync-options {
  margin-top: 16px;
  padding-left: 26px;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
}

.form-input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
}

.form-dropdown {
  width: 100%;
}
</style>

