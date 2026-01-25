<template>
  <div class="environment-config-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Environment Configuration Testing</h1>
          <p class="page-description">Validate environment variables, secrets management, configuration drift, and environment policies</p>
        </div>
        <button @click="showTestModal = true" class="btn-primary">
          <Play class="btn-icon" />
          Run Test
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

    <!-- Environment Validation Tab -->
    <div v-if="activeTab === 'validation'" class="tab-content">
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search environments..."
          class="search-input"
        />
        <Dropdown
          v-model="filterEnvironment"
          :options="environmentOptions"
          placeholder="All Environments"
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
          v-for="result in filteredValidationResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.environment }}</h3>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <div class="result-meta">
              <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>

          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Variables Validated:</span>
              <span class="detail-value">{{ result.validatedVariables }}/{{ result.totalVariables }}</span>
            </div>
            <div v-if="result.issues && result.issues.length > 0" class="detail-row">
              <span class="detail-label">Issues Found:</span>
              <span class="detail-value value-error">{{ result.issues.length }}</span>
            </div>
            <div v-if="result.secretsDetected && result.secretsDetected.length > 0" class="detail-row">
              <span class="detail-label">Secrets Detected:</span>
              <span class="detail-value value-warning">{{ result.secretsDetected.length }}</span>
            </div>
          </div>

          <div v-if="result.issues && result.issues.length > 0" class="result-issues">
            <div
              v-for="issue in result.issues.slice(0, 3)"
              :key="issue.field"
              class="issue-item"
              :class="`issue-${issue.severity}`"
            >
              <AlertTriangle class="issue-icon" />
              <span>{{ issue.message }}</span>
            </div>
            <div v-if="result.issues.length > 3" class="issue-more">
              +{{ result.issues.length - 3 }} more issues
            </div>
          </div>
        </div>
      </div>

      <div v-if="filteredValidationResults.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No validation results found</h3>
        <p>Run environment validation tests to see results here</p>
      </div>
    </div>

    <!-- Secrets Management Tab -->
    <div v-if="activeTab === 'secrets'" class="tab-content">
      <div class="results-grid">
        <div
          v-for="result in secretsResults"
          :key="result.id"
          class="result-card"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.type }}</h3>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
          </div>

          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Secrets Tested:</span>
              <span class="detail-value">{{ result.secretsTested }}</span>
            </div>
            <div v-if="result.rotationPolicies" class="detail-row">
              <span class="detail-label">Rotation Policies:</span>
              <span class="detail-value">{{ result.rotationPolicies.length }}</span>
            </div>
            <div v-if="result.accessControls" class="detail-row">
              <span class="detail-label">Access Controls:</span>
              <span class="detail-value">{{ result.accessControls.length }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Configuration Drift Tab -->
    <div v-if="activeTab === 'drift'" class="tab-content">
      <div class="filters">
        <Dropdown
          v-model="driftBaseline"
          :options="environmentOptions"
          placeholder="Baseline Environment"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="driftCurrent"
          :options="environmentOptions"
          placeholder="Current Environment"
          class="filter-dropdown"
        />
        <button @click="detectDrift" class="btn-primary" :disabled="!driftBaseline || !driftCurrent">
          Detect Drift
        </button>
      </div>

      <div v-if="driftResult" class="drift-result">
        <div class="drift-header">
          <h3>Drift Detection Results</h3>
          <span class="drift-status" :class="driftResult.hasDrift ? 'status-failed' : 'status-passed'">
            {{ driftResult.hasDrift ? 'Drift Detected' : 'No Drift' }}
          </span>
        </div>
        <div v-if="driftResult.differences && driftResult.differences.length > 0" class="drift-differences">
          <h4>Differences Found:</h4>
          <div
            v-for="diff in driftResult.differences"
            :key="diff.field"
            class="drift-item"
          >
            <span class="drift-field">{{ diff.field }}</span>
            <span class="drift-change">{{ diff.change }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Environment Policies Tab -->
    <div v-if="activeTab === 'policies'" class="tab-content">
      <div class="results-grid">
        <div
          v-for="result in policyResults"
          :key="result.id"
          class="result-card"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h3 class="result-name">{{ result.environment }}</h3>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
          </div>

          <div class="result-details">
            <div class="detail-row">
              <span class="detail-label">Isolation Tests:</span>
              <span class="detail-value">{{ result.isolationTests?.passed ? 'Passed' : 'Failed' }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Promotion Rules:</span>
              <span class="detail-value">{{ result.promotionRules?.length || 0 }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showTestModal" class="modal-overlay" @click="closeTestModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Run Environment Configuration Test</h2>
              <button @click="closeTestModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="runTest" class="test-form">
                <div class="form-group">
                  <label>Test Type *</label>
                  <select v-model="testForm.type" required>
                    <option value="validation">Environment Validation</option>
                    <option value="secrets">Secrets Management</option>
                    <option value="drift">Configuration Drift</option>
                    <option value="policies">Environment Policies</option>
                  </select>
                </div>

                <div class="form-group">
                  <label>Environment *</label>
                  <select v-model="testForm.environment" required>
                    <option value="dev">Development</option>
                    <option value="staging">Staging</option>
                    <option value="prod">Production</option>
                  </select>
                </div>

                <div v-if="testForm.type === 'secrets'" class="form-group">
                  <label>Secrets Manager Type *</label>
                  <select v-model="testForm.secretsType" required>
                    <option value="vault">HashiCorp Vault</option>
                    <option value="aws-secrets-manager">AWS Secrets Manager</option>
                    <option value="azure-key-vault">Azure Key Vault</option>
                    <option value="gcp-secret-manager">GCP Secret Manager</option>
                    <option value="kubernetes">Kubernetes</option>
                  </select>
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeTestModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="runningTest">
                    {{ runningTest ? 'Running...' : 'Run Test' }}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

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
                    <span :class="selectedResult.passed ? 'value-success' : 'value-error'">
                      {{ selectedResult.passed ? 'Passed' : 'Failed' }}
                    </span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Environment:</span>
                    <span>{{ selectedResult.environment }}</span>
                  </div>
                  <div class="detail-item">
                    <span class="detail-label">Timestamp:</span>
                    <span>{{ formatDate(selectedResult.timestamp) }}</span>
                  </div>
                </div>
              </div>

              <div v-if="selectedResult.issues && selectedResult.issues.length > 0" class="detail-section">
                <h3>Issues ({{ selectedResult.issues.length }})</h3>
                <div
                  v-for="issue in selectedResult.issues"
                  :key="issue.field"
                  class="issue-card"
                  :class="`issue-${issue.severity}`"
                >
                  <div class="issue-header">
                    <span class="issue-type">{{ issue.type }}</span>
                    <span class="issue-severity">{{ issue.severity }}</span>
                  </div>
                  <p class="issue-message">{{ issue.message }}</p>
                  <p v-if="issue.recommendation" class="issue-recommendation">
                    <strong>Recommendation:</strong> {{ issue.recommendation }}
                  </p>
                </div>
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
import { Teleport } from 'vue';
import axios from 'axios';
import {
  Shield,
  KeyRound,
  GitCompare,
  FileCheck,
  Play,
  X,
  AlertTriangle
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Environment Configuration Testing' }
];

const activeTab = ref<'validation' | 'secrets' | 'drift' | 'policies'>('validation');
const searchQuery = ref('');
const filterEnvironment = ref('');
const filterStatus = ref('');
const showTestModal = ref(false);
const showDetailModal = ref(false);
const selectedResult = ref<any>(null);
const runningTest = ref(false);
const driftBaseline = ref('');
const driftCurrent = ref('');
const driftResult = ref<any>(null);

const tabs = computed(() => [
  { id: 'validation', label: 'Environment Validation', icon: Shield },
  { id: 'secrets', label: 'Secrets Management', icon: KeyRound },
  { id: 'drift', label: 'Configuration Drift', icon: GitCompare },
  { id: 'policies', label: 'Environment Policies', icon: FileCheck }
]);

const testForm = ref({
  type: 'validation',
  environment: 'dev',
  secretsType: 'vault'
});

const environmentOptions = [
  { value: '', label: 'All Environments' },
  { value: 'dev', label: 'Development' },
  { value: 'staging', label: 'Staging' },
  { value: 'prod', label: 'Production' }
];

const statusOptions = [
  { value: '', label: 'All Statuses' },
  { value: 'passed', label: 'Passed' },
  { value: 'failed', label: 'Failed' }
];

// Mock data - in production, this would come from API
const validationResults = ref<any[]>([]);
const secretsResults = ref<any[]>([]);
const policyResults = ref<any[]>([]);

const filteredValidationResults = computed(() => {
  let results = validationResults.value;
  
  if (searchQuery.value) {
    results = results.filter(r => 
      r.environment.toLowerCase().includes(searchQuery.value.toLowerCase())
    );
  }
  
  if (filterEnvironment.value) {
    results = results.filter(r => r.environment === filterEnvironment.value);
  }
  
  if (filterStatus.value) {
    results = results.filter(r => 
      filterStatus.value === 'passed' ? r.passed : !r.passed
    );
  }
  
  return results;
});

const runTest = async () => {
  runningTest.value = true;
  try {
    let response;
    const baseUrl = '/api/environment-config';
    
    switch (testForm.value.type) {
      case 'validation':
        response = await axios.post(`${baseUrl}/validate`, {
          environment: testForm.value.environment,
          variables: {},
          configFiles: [],
          secrets: []
        });
        validationResults.value.unshift({
          id: Date.now().toString(),
          ...response.data,
          timestamp: new Date()
        });
        break;
      case 'secrets':
        response = await axios.post(`${baseUrl}/validate-secrets`, {
          type: testForm.value.secretsType,
          connection: {}
        });
        secretsResults.value.unshift({
          id: Date.now().toString(),
          ...response.data,
          timestamp: new Date()
        });
        break;
      case 'policies':
        response = await axios.post(`${baseUrl}/validate-policies`, {
          environment: testForm.value.environment,
          policies: [],
          isolationRules: [],
          promotionRules: []
        });
        policyResults.value.unshift({
          id: Date.now().toString(),
          ...response.data,
          timestamp: new Date()
        });
        break;
    }
    
    closeTestModal();
  } catch (error: any) {
    console.error('Error running test:', error);
    alert(error.response?.data?.message || 'Failed to run test');
  } finally {
    runningTest.value = false;
  }
};

const detectDrift = async () => {
  try {
    const response = await axios.post('/api/environment-config/detect-drift', {
      baselineEnvironment: driftBaseline.value,
      currentEnvironment: driftCurrent.value,
      variables: {},
      currentVariables: {},
      configFiles: [],
      currentConfigFiles: []
    });
    driftResult.value = response.data;
  } catch (error: any) {
    console.error('Error detecting drift:', error);
    alert(error.response?.data?.message || 'Failed to detect drift');
  }
};

const viewResultDetails = (result: any) => {
  selectedResult.value = result;
  showDetailModal.value = true;
};

const closeTestModal = () => {
  showTestModal.value = false;
  testForm.value = {
    type: 'validation',
    environment: 'dev',
    secretsType: 'vault'
  };
};

const closeDetailModal = () => {
  showDetailModal.value = false;
  selectedResult.value = null;
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
    minute: '2-digit'
  }).format(date);
};

onMounted(() => {
  // Load initial data if needed
});
</script>

<style scoped>
.environment-config-page {
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
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  margin: 0 0 var(--spacing-sm) 0;
  color: var(--color-text-primary);
}

.page-description {
  color: var(--color-text-secondary);
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: 10px var(--spacing-xl);
  background: var(--gradient-primary);
  color: var(--color-text-primary);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: opacity 0.2s;
}

.btn-primary:hover {
  opacity: 0.9;
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
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
  cursor: pointer;
  transition: var(--transition-all);
  font-weight: var(--font-weight-medium);
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
  background: var(--color-info-bg);
  padding: 2px var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.search-input {
  flex: 1;
  padding: 10px var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
}

.filter-dropdown {
  min-width: 180px;
}

.results-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-xl);
}

.result-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  cursor: pointer;
  transition: var(--transition-all);
}

.result-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.result-header {
  margin-bottom: var(--spacing-md);
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.result-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  margin: 0;
  color: var(--color-text-primary);
}

.result-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.status-passed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.result-meta {
  display: flex;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.result-details {
  margin-bottom: var(--spacing-md);
}

.detail-row {
  display: flex;
  justify-content: space-between;
  padding: var(--spacing-sm) 0;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.detail-label {
  color: var(--color-text-secondary);
}

.detail-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.value-success {
  color: var(--color-success);
}

.value-error {
  color: var(--color-error);
}

.value-warning {
  color: var(--color-warning);
}

.result-issues {
  margin-top: 16px;
}

.issue-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  margin-bottom: 8px;
  border-radius: 6px;
  font-size: 0.875rem;
}

.issue-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.issue-high {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.issue-medium {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.issue-low {
  background: rgba(79, 172, 254, 0.1);
  color: var(--color-primary);
}

.issue-icon {
  width: 16px;
  height: 16px;
}

.issue-more {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  padding-left: var(--spacing-lg);
}

.empty-state {
  text-align: center;
  padding: 60px var(--spacing-xl);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto var(--spacing-xl);
  opacity: 0.5;
}

.drift-result {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.drift-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.drift-differences {
  margin-top: 20px;
}

.drift-item {
  display: flex;
  justify-content: space-between;
  padding: 12px;
  margin-bottom: 8px;
  background: rgba(79, 172, 254, 0.05);
  border-radius: 6px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: #1a1f2e;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  width: 90%;
  max-width: 600px;
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
  padding: 20px 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  margin: 0;
  color: #e2e8f0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #94a3b8;
  cursor: pointer;
  padding: 4px;
}

.modal-close:hover {
  color: #e2e8f0;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.test-form {
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
  color: #e2e8f0;
  font-weight: 500;
}

.form-group select,
.form-group input {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #e2e8f0;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.detail-section {
  margin-bottom: 24px;
}

.detail-section h3 {
  color: #e2e8f0;
  margin-bottom: 16px;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.issue-card {
  padding: 16px;
  margin-bottom: 12px;
  border-radius: 8px;
  border-left: 3px solid;
}

.issue-card.issue-critical {
  background: rgba(239, 68, 68, 0.1);
  border-color: #ef4444;
}

.issue-card.issue-high {
  background: rgba(239, 68, 68, 0.1);
  border-color: #f87171;
}

.issue-card.issue-medium {
  background: rgba(245, 158, 11, 0.1);
  border-color: #f59e0b;
}

.issue-card.issue-low {
  background: rgba(79, 172, 254, 0.1);
  border-color: #4facfe;
}

.issue-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 8px;
}

.issue-type {
  font-weight: 600;
  color: #e2e8f0;
}

.issue-severity {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.issue-message {
  color: #94a3b8;
  margin: 8px 0;
}

.issue-recommendation {
  color: #cbd5e1;
  margin-top: 8px;
  font-size: 0.875rem;
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
</style>

