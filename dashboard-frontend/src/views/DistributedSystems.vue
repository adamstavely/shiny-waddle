<template>
  <div class="distributed-systems-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Distributed Systems Testing</h1>
          <p class="page-description">
            Test access control and compliance across distributed systems, multi-region deployments, and microservices
          </p>
        </div>
      </div>
    </div>

    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        :class="['tab-button', { active: activeTab === tab.id }]"
      >
        {{ tab.label }}
      </button>
    </div>

    <!-- Multi-Region Testing Tab -->
    <div v-if="activeTab === 'multi-region'" class="tab-content">
      <DistributedTestRunner />
    </div>

    <!-- Policy Consistency Tab -->
    <div v-if="activeTab === 'consistency'" class="tab-content">
      <div class="consistency-section">
        <h2>Policy Consistency Testing</h2>
        <p>Compare policies across regions to detect inconsistencies</p>

        <div class="form-section">
          <div class="form-group">
            <label>Application</label>
            <select v-model="consistencyConfig.applicationId" @change="loadConsistencyRegions">
              <option value="">Select Application</option>
              <option v-for="app in applications" :key="app.id" :value="app.id">
                {{ app.name }}
              </option>
            </select>
          </div>

          <div v-if="consistencyRegions.length > 0" class="form-group">
            <label>Regions to Check</label>
            <div class="region-checkboxes">
              <label v-for="region in consistencyRegions" :key="region.id" class="checkbox-label">
                <input
                  type="checkbox"
                  :value="region.id"
                  v-model="consistencyConfig.regions"
                />
                {{ region.name }} ({{ region.id }})
              </label>
            </div>
          </div>

          <div class="form-group">
            <label>Check Types</label>
            <div class="region-checkboxes">
              <label class="checkbox-label">
                <input type="checkbox" value="version" v-model="consistencyConfig.checkTypes" />
                Version Consistency
              </label>
              <label class="checkbox-label">
                <input type="checkbox" value="configuration" v-model="consistencyConfig.checkTypes" />
                Configuration Consistency
              </label>
              <label class="checkbox-label">
                <input type="checkbox" value="evaluation" v-model="consistencyConfig.checkTypes" />
                Evaluation Consistency
              </label>
            </div>
          </div>

          <button @click="runConsistencyCheck" :disabled="consistencyLoading" class="btn-primary">
            <Play v-if="!consistencyLoading" class="btn-icon" />
            <span v-if="consistencyLoading">Checking...</span>
            <span v-else>Check Consistency</span>
          </button>
        </div>

        <div v-if="consistencyReport" class="consistency-results">
          <h3>Consistency Report</h3>
          <div class="report-summary">
            <div class="summary-item" :class="{ 'consistent': consistencyReport.consistent, 'inconsistent': !consistencyReport.consistent }">
              <span class="summary-label">Status:</span>
              <span class="summary-value">{{ consistencyReport.consistent ? 'CONSISTENT' : 'INCONSISTENT' }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Total Policies:</span>
              <span class="summary-value">{{ consistencyReport.summary.totalPolicies }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Consistent:</span>
              <span class="summary-value">{{ consistencyReport.summary.consistentPolicies }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Inconsistent:</span>
              <span class="summary-value">{{ consistencyReport.summary.inconsistentPolicies }}</span>
            </div>
          </div>

          <div v-if="consistencyReport.inconsistencies.length > 0" class="inconsistencies-list">
            <h4>Inconsistencies</h4>
            <div v-for="(inconsistency, index) in consistencyReport.inconsistencies" :key="index" class="inconsistency-item">
              <div class="inconsistency-header">
                <span class="policy-name">{{ inconsistency.policyName }}</span>
                <span class="severity-badge" :class="`severity-${inconsistency.severity}`">
                  {{ inconsistency.severity }}
                </span>
              </div>
              <div class="inconsistency-details">
                <div>Type: {{ inconsistency.inconsistencyType }}</div>
                <div>Regions: {{ inconsistency.regions.join(', ') }}</div>
                <div v-if="inconsistency.recommendation" class="recommendation">
                  Recommendation: {{ inconsistency.recommendation }}
                </div>
              </div>
            </div>
          </div>

          <div v-if="consistencyReport.recommendations.length > 0" class="recommendations">
            <h4>Recommendations</h4>
            <ul>
              <li v-for="(rec, index) in consistencyReport.recommendations" :key="index">
                {{ rec }}
              </li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Policy Synchronization Tab -->
    <div v-if="activeTab === 'synchronization'" class="tab-content">
      <div class="sync-section">
        <h2>Policy Synchronization Testing</h2>
        <p>Test policy synchronization across regions and measure sync latency</p>

        <div class="form-section">
          <div class="form-group">
            <label>Application</label>
            <select v-model="syncConfig.applicationId" @change="loadSyncRegions">
              <option value="">Select Application</option>
              <option v-for="app in applications" :key="app.id" :value="app.id">
                {{ app.name }}
              </option>
            </select>
          </div>

          <div v-if="syncRegions.length > 0" class="form-group">
            <label>Regions to Test</label>
            <div class="region-checkboxes">
              <label v-for="region in syncRegions" :key="region.id" class="checkbox-label">
                <input
                  type="checkbox"
                  :value="region.id"
                  v-model="syncConfig.regions"
                />
                {{ region.name }} ({{ region.id }})
              </label>
            </div>
          </div>

          <div class="form-group">
            <label>Test Scenarios</label>
            <div class="region-checkboxes">
              <label class="checkbox-label">
                <input type="checkbox" value="update-propagation" v-model="syncConfig.testScenarios" />
                Update Propagation
              </label>
              <label class="checkbox-label">
                <input type="checkbox" value="sync-timing" v-model="syncConfig.testScenarios" />
                Sync Timing
              </label>
              <label class="checkbox-label">
                <input type="checkbox" value="sync-failure-recovery" v-model="syncConfig.testScenarios" />
                Sync Failure Recovery
              </label>
            </div>
          </div>

          <button @click="runSyncTest" :disabled="syncLoading" class="btn-primary">
            <Play v-if="!syncLoading" class="btn-icon" />
            <span v-if="syncLoading">Testing...</span>
            <span v-else>Test Synchronization</span>
          </button>
        </div>

        <div v-if="syncReport" class="sync-results">
          <h3>Synchronization Report</h3>
          <div class="report-summary">
            <div class="summary-item">
              <span class="summary-label">Total Tests:</span>
              <span class="summary-value">{{ syncReport.summary.totalTests }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Passed:</span>
              <span class="summary-value">{{ syncReport.summary.passedTests }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Failed:</span>
              <span class="summary-value">{{ syncReport.summary.failedTests }}</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Avg Sync Latency:</span>
              <span class="summary-value">{{ Math.round(syncReport.summary.averageSyncLatency) }}ms</span>
            </div>
            <div class="summary-item">
              <span class="summary-label">Sync Failures:</span>
              <span class="summary-value">{{ syncReport.summary.syncFailures }}</span>
            </div>
          </div>

          <div class="test-results-list">
            <h4>Test Results</h4>
            <div v-for="(testResult, index) in syncReport.testResults" :key="index" class="test-result-item">
              <div class="test-result-header">
                <span class="test-scenario">{{ testResult.scenario }}</span>
                <span class="test-status" :class="{ 'passed': testResult.passed, 'failed': !testResult.passed }">
                  {{ testResult.passed ? '✓ PASSED' : '✗ FAILED' }}
                </span>
              </div>
              <div class="test-result-details">
                <div>Sync Latency: {{ testResult.syncLatency || 'N/A' }}ms</div>
                <div>Regions In Sync: {{ testResult.syncStatus.regionsInSync.join(', ') }}</div>
                <div v-if="testResult.syncStatus.regionsOutOfSync.length > 0">
                  Regions Out of Sync: {{ testResult.syncStatus.regionsOutOfSync.join(', ') }}
                </div>
              </div>
            </div>
          </div>

          <div v-if="syncReport.recommendations.length > 0" class="recommendations">
            <h4>Recommendations</h4>
            <ul>
              <li v-for="(rec, index) in syncReport.recommendations" :key="index">
                {{ rec }}
              </li>
            </ul>
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
import { ref, onMounted } from 'vue';
import { Play } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import DistributedTestRunner from '../components/DistributedTestRunner.vue';
import { useDistributedTesting } from '../composables/useDistributedTesting';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Distributed Systems' },
];

const { checkPolicyConsistency, testPolicySynchronization, loading: consistencyLoading, error } = useDistributedTesting();
const syncLoading = ref(false);

const activeTab = ref('multi-region');
const tabs = [
  { id: 'multi-region', label: 'Multi-Region Testing' },
  { id: 'consistency', label: 'Policy Consistency' },
  { id: 'synchronization', label: 'Policy Synchronization' },
];

const applications = ref<any[]>([]);
const consistencyRegions = ref<any[]>([]);
const syncRegions = ref<any[]>([]);

const consistencyConfig = ref({
  applicationId: '',
  regions: [] as string[],
  checkTypes: ['version', 'configuration'] as string[],
});

const syncConfig = ref({
  applicationId: '',
  regions: [] as string[],
  testScenarios: ['update-propagation', 'sync-timing'] as string[],
});

const consistencyReport = ref<any>(null);
const syncReport = ref<any>(null);

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/v1/applications');
    applications.value = response.data || [];
  } catch (err: any) {
    console.error('Failed to load applications:', err);
  }
};

const loadConsistencyRegions = async () => {
  if (!consistencyConfig.value.applicationId) {
    consistencyRegions.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/applications/${consistencyConfig.value.applicationId}`);
    const app = response.data;
    if (app.infrastructure?.distributedSystems?.regions) {
      consistencyRegions.value = app.infrastructure.distributedSystems.regions;
      consistencyConfig.value.regions = consistencyRegions.value.map((r: any) => r.id);
    } else {
      consistencyRegions.value = [];
    }
  } catch (err: any) {
    console.error('Failed to load regions:', err);
    consistencyRegions.value = [];
  }
};

const loadSyncRegions = async () => {
  if (!syncConfig.value.applicationId) {
    syncRegions.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/applications/${syncConfig.value.applicationId}`);
    const app = response.data;
    if (app.infrastructure?.distributedSystems?.regions) {
      syncRegions.value = app.infrastructure.distributedSystems.regions;
      syncConfig.value.regions = syncRegions.value.map((r: any) => r.id);
    } else {
      syncRegions.value = [];
    }
  } catch (err: any) {
    console.error('Failed to load regions:', err);
    syncRegions.value = [];
  }
};

const runConsistencyCheck = async () => {
  consistencyReport.value = null;
  try {
    const report = await checkPolicyConsistency({
      applicationId: consistencyConfig.value.applicationId,
      regions: consistencyConfig.value.regions,
      checkTypes: consistencyConfig.value.checkTypes as any,
    });
    consistencyReport.value = report;
  } catch (err) {
    console.error('Consistency check failed:', err);
  }
};

const runSyncTest = async () => {
  syncReport.value = null;
  syncLoading.value = true;
  try {
    const report = await testPolicySynchronization({
      applicationId: syncConfig.value.applicationId,
      regions: syncConfig.value.regions,
      testScenarios: syncConfig.value.testScenarios as any,
    });
    syncReport.value = report;
  } catch (err) {
    console.error('Sync test failed:', err);
  } finally {
    syncLoading.value = false;
  }
};

onMounted(() => {
  loadApplications();
});
</script>

<style scoped>
.distributed-systems-page {
  padding: 2rem;
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
}

.page-header {
  margin-bottom: 2rem;
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0 0 0.5rem 0;
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
  margin: 0;
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: 2rem;
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-button {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  cursor: pointer;
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  position: relative;
  bottom: -1px;
}

.tab-button:hover {
  color: var(--color-text-primary);
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
  background: rgba(79, 172, 254, 0.05);
}

.tab-content {
  min-height: 400px;
  animation: fadeIn 0.3s;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.consistency-section,
.sync-section {
  max-width: 1200px;
}

.consistency-section h2,
.sync-section h2 {
  margin-top: 0;
  margin-bottom: 0.5rem;
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.consistency-section p,
.sync-section p {
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.form-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  margin: var(--spacing-xl) 0;
}

.form-group {
  margin-bottom: var(--spacing-lg);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.form-group select,
.form-group input {
  width: 100%;
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.form-group select:focus,
.form-group input:focus {
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

.consistency-results,
.sync-results {
  margin-top: var(--spacing-xl);
  padding-top: var(--spacing-xl);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.consistency-results h3,
.sync-results h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-lg);
}

.report-summary {
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

.summary-item.consistent {
  border-color: rgba(34, 197, 94, 0.4);
  background: rgba(34, 197, 94, 0.05);
}

.summary-item.inconsistent {
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

.inconsistencies-list {
  margin-top: var(--spacing-xl);
}

.inconsistencies-list h4 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.inconsistency-item {
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-md);
}

.inconsistency-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.policy-name {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: uppercase;
}

.severity-critical {
  background: rgba(239, 68, 68, 0.2);
  color: #fc8181;
}

.severity-high {
  background: rgba(251, 146, 60, 0.2);
  color: #fb923c;
}

.severity-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-low {
  background: rgba(96, 165, 250, 0.2);
  color: #93c5fd;
}

.inconsistency-details {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.recommendation {
  margin-top: var(--spacing-sm);
  font-style: italic;
  color: var(--color-text-secondary);
}

.recommendations {
  margin-top: var(--spacing-xl);
}

.recommendations h4 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.recommendations ul {
  list-style-type: disc;
  padding-left: var(--spacing-xl);
  color: var(--color-text-secondary);
}

.recommendations li {
  margin-bottom: var(--spacing-sm);
}

.test-results-list {
  margin-top: var(--spacing-xl);
}

.test-results-list h4 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.test-result-item {
  padding: var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-md);
}

.test-result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.test-scenario {
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
  color: var(--color-text-primary);
}

.test-status {
  font-weight: var(--font-weight-semibold);
}

.test-status.passed {
  color: #22c55e;
}

.test-status.failed {
  color: #ef4444;
}

.test-result-details {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
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
