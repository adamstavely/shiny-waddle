<template>
  <div class="distributed-test-runner">
    <div class="test-configuration">
      <h3>Test Configuration</h3>
      
      <div class="form-group">
        <label>Test Name</label>
        <input v-model="testConfig.name" type="text" placeholder="Enter test name" />
      </div>

      <div class="form-group">
        <label>Test Type</label>
        <select v-model="testConfig.testType">
          <option value="access-control">Access Control</option>
          <option value="policy-consistency">Policy Consistency</option>
          <option value="synchronization">Synchronization</option>
        </select>
      </div>

      <div class="form-group">
        <label>Application</label>
        <select v-model="testConfig.applicationId" @change="loadRegions">
          <option value="">Select Application</option>
          <option v-for="app in applications" :key="app.id" :value="app.id">
            {{ app.name }}
          </option>
        </select>
      </div>

      <div v-if="regions.length > 0" class="form-group">
        <label>Regions to Test</label>
        <div class="region-checkboxes">
          <label v-for="region in regions" :key="region.id" class="checkbox-label">
            <input
              type="checkbox"
              :value="region.id"
              v-model="testConfig.regions"
            />
            {{ region.name }} ({{ region.id }})
          </label>
        </div>
      </div>

      <div v-if="testConfig.testType === 'access-control'" class="form-group">
        <label>User ID</label>
        <input v-model="testConfig.user.id" type="text" placeholder="user-123" />
      </div>

      <div v-if="testConfig.testType === 'access-control'" class="form-group">
        <label>Resource ID</label>
        <input v-model="testConfig.resource.id" type="text" placeholder="resource-456" />
      </div>

      <div class="form-group">
        <label>Execution Mode</label>
        <select v-model="testConfig.executionMode">
          <option value="parallel">Parallel</option>
          <option value="sequential">Sequential</option>
        </select>
      </div>

      <div class="form-group">
        <label>Timeout (ms)</label>
        <input v-model.number="testConfig.timeout" type="number" placeholder="30000" />
      </div>

      <button @click="runTest" :disabled="loading || !canRunTest" class="btn-primary">
        <Play v-if="!loading" class="btn-icon" />
        <span v-if="loading">Running...</span>
        <span v-else>Run Test</span>
      </button>
    </div>

    <div v-if="testResult" class="test-results">
      <h3>Test Results</h3>
      
      <div class="result-summary">
        <div class="summary-item" :class="{ 'passed': testResult.passed, 'failed': !testResult.passed }">
          <span class="summary-label">Status:</span>
          <span class="summary-value">{{ testResult.passed ? 'PASSED' : 'FAILED' }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Total Regions:</span>
          <span class="summary-value">{{ testResult.aggregatedResult.totalRegions }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Successful:</span>
          <span class="summary-value">{{ testResult.aggregatedResult.successfulRegions }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Failed:</span>
          <span class="summary-value">{{ testResult.aggregatedResult.failedRegions }}</span>
        </div>
        <div class="summary-item">
          <span class="summary-label">Avg Execution Time:</span>
          <span class="summary-value">{{ testResult.aggregatedResult.averageExecutionTime }}ms</span>
        </div>
      </div>

      <div class="region-results">
        <h4>Region Results</h4>
        <div v-for="regionResult in testResult.regionResults" :key="regionResult.regionId" class="region-result-item">
          <div class="region-header">
            <span class="region-name">{{ regionResult.regionName }}</span>
            <span class="region-status" :class="{ 'passed': regionResult.testResult.passed, 'failed': !regionResult.testResult.passed }">
              {{ regionResult.testResult.passed ? '✓' : '✗' }}
            </span>
          </div>
          <div class="region-details">
            <div>Execution Time: {{ regionResult.executionTime }}ms</div>
            <div v-if="regionResult.error" class="error-message">
              Error: {{ regionResult.error }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <div v-if="error" class="error-banner">
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Play } from 'lucide-vue-next';
import { useDistributedTesting } from '../composables/useDistributedTesting';
import axios from 'axios';

const { executeMultiRegionTest, loading, error } = useDistributedTesting();

const applications = ref<any[]>([]);
const regions = ref<any[]>([]);

const testConfig = ref({
  name: '',
  testType: 'access-control' as 'access-control' | 'policy-consistency' | 'synchronization',
  applicationId: '',
  regions: [] as string[],
  user: {
    id: '',
  },
  resource: {
    id: '',
  },
  executionMode: 'parallel' as 'parallel' | 'sequential',
  timeout: 30000,
});

const testResult = ref<any>(null);

const canRunTest = computed(() => {
  return (
    testConfig.value.name &&
    testConfig.value.applicationId &&
    testConfig.value.regions.length > 0
  );
});

const loadRegions = async () => {
  if (!testConfig.value.applicationId) {
    regions.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/applications/${testConfig.value.applicationId}`);
    const app = response.data;
    if (app.infrastructure?.distributedSystems?.regions) {
      regions.value = app.infrastructure.distributedSystems.regions;
      testConfig.value.regions = regions.value.map((r: any) => r.id);
    } else {
      regions.value = [];
    }
  } catch (err: any) {
    console.error('Failed to load regions:', err);
    regions.value = [];
  }
};

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/v1/applications');
    applications.value = response.data || [];
  } catch (err: any) {
    console.error('Failed to load applications:', err);
  }
};

const runTest = async () => {
  testResult.value = null;
  try {
    const result = await executeMultiRegionTest({
      name: testConfig.value.name,
      testType: testConfig.value.testType,
      applicationId: testConfig.value.applicationId,
      regions: testConfig.value.regions,
      user: testConfig.value.user.id ? {
        id: testConfig.value.user.id,
      } : undefined,
      resource: testConfig.value.resource.id ? {
        id: testConfig.value.resource.id,
      } : undefined,
      executionMode: testConfig.value.executionMode,
      timeout: testConfig.value.timeout,
    });
    testResult.value = result;
  } catch (err) {
    console.error('Test execution failed:', err);
  }
};

onMounted(() => {
  loadApplications();
});
</script>

<style scoped>
.distributed-test-runner {
  padding: var(--spacing-lg);
}

.test-configuration {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  margin-bottom: var(--spacing-xl);
}

.test-configuration h3 {
  margin-top: 0;
  margin-bottom: var(--spacing-lg);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.form-group {
  margin-bottom: var(--spacing-md);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.form-group input,
.form-group select {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.region-checkboxes {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-weight: normal;
  color: var(--color-text-secondary);
  cursor: pointer;
}

.checkbox-label input[type="checkbox"] {
  width: auto;
  margin: 0;
  cursor: pointer;
}

.btn-primary {
  margin-top: var(--spacing-md);
  display: inline-flex;
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
  font-size: var(--font-size-sm);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
  transform: none;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.test-results {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
}

.test-results h3 {
  margin-top: 0;
  margin-bottom: var(--spacing-lg);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.result-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.summary-item {
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.summary-item.passed {
  border-color: rgba(34, 197, 94, 0.4);
  background: rgba(34, 197, 94, 0.05);
}

.summary-item.failed {
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.05);
}

.summary-label {
  display: block;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.summary-value {
  display: block;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.region-results {
  margin-top: var(--spacing-xl);
}

.region-results h4 {
  margin-bottom: var(--spacing-md);
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.region-result-item {
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-sm);
}

.region-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.region-name {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.region-status {
  font-size: var(--font-size-xl);
}

.region-status.passed {
  color: #22c55e;
}

.region-status.failed {
  color: #ef4444;
}

.region-details {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.error-message {
  color: #ef4444;
  margin-top: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.error-banner {
  background: rgba(239, 68, 68, 0.1);
  border: var(--border-width-thin) solid rgba(239, 68, 68, 0.3);
  color: #fc8181;
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  margin-top: var(--spacing-md);
}
</style>
