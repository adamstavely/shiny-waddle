<template>
  <div class="test-detail-page">
    <div v-if="loading" class="loading">Loading test...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && test" class="test-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <div class="test-title-row">
              <h1 class="page-title">{{ test.name }}</h1>
              <span class="version-badge">v{{ test.version }}</span>
            </div>
            <p class="test-meta">
              {{ getTestTypeLabel(test.testType) }}
            </p>
            <p v-if="test.description" class="test-description">{{ test.description }}</p>
          </div>
          <div class="header-actions">
            <button @click="editTest" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="viewVersions" class="action-btn view-btn">
              <History class="action-icon" />
              Versions
            </button>
            <button @click="deleteTest" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
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
        </button>
      </div>

      <!-- Overview Tab -->
      <div v-if="activeTab === 'overview'" class="tab-content">
        <div class="overview-grid">
          <CrossLinkPanel
            v-if="test"
            entity-type="test"
            :entity-id="test.id"
          />
          <div class="info-card">
            <h3 class="card-title">
              <Info class="title-icon" />
              Test Information
            </h3>
            <div class="info-list">
              <div class="info-item">
                <span class="info-label">Type</span>
                <span class="info-value">{{ getTestTypeLabel(test.testType) }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Version</span>
                <span class="info-value">{{ test.version }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Created</span>
                <span class="info-value">{{ formatDate(test.createdAt) }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Last Updated</span>
                <span class="info-value">{{ formatDate(test.updatedAt) }}</span>
              </div>
              <div v-if="test.createdBy" class="info-item">
                <span class="info-label">Created By</span>
                <span class="info-value">{{ test.createdBy }}</span>
              </div>
            </div>
          </div>

          <!-- Access Control Specific Info -->
          <div v-if="test.testType === 'access-control'" class="info-card">
            <h3 class="card-title">
              <Shield class="title-icon" />
              Access Control Configuration
            </h3>
            <div class="info-list">
              <div v-if="test.inputs?.subject?.role" class="info-item">
                <span class="info-label">Role</span>
                <span class="info-value">{{ test.inputs.subject.role }}</span>
              </div>
              <div v-if="test.inputs?.resource" class="info-item">
                <span class="info-label">Resource</span>
                <span class="info-value">{{ test.inputs.resource?.type || test.inputs.resource?.id }}</span>
              </div>
              <div v-if="test.expected" class="info-item">
                <span class="info-label">Expected Decision</span>
                <span class="info-value" :class="test.expected.allowed ? 'allowed' : 'denied'">
                  {{ test.expected.allowed ? 'Allow' : 'Deny' }}
                </span>
              </div>
            </div>
          </div>

          <!-- Distributed Systems Specific Info -->
          <div v-if="test.testType === 'distributed-systems'" class="info-card">
            <h3 class="card-title">
              <Network class="title-icon" />
              Distributed Systems Configuration
            </h3>
            <div class="info-list">
              <div v-if="test.distributedTestType" class="info-item">
                <span class="info-label">Test Subtype</span>
                <span class="info-value">{{ getDistributedTestTypeLabel(test.distributedTestType) }}</span>
              </div>
              <div v-if="test.applicationId" class="info-item">
                <span class="info-label">Application</span>
                <span class="info-value">{{ getApplicationName(test.applicationId) || test.applicationId }}</span>
              </div>
              
              <!-- Multi-Region Config -->
              <div v-if="test.distributedTestType === 'multi-region' && test.multiRegionConfig" class="config-section">
                <h4 class="config-section-title">Multi-Region Configuration</h4>
                <div v-if="test.multiRegionConfig.regions" class="info-item">
                  <span class="info-label">Regions</span>
                  <span class="info-value">{{ test.multiRegionConfig.regions.join(', ') }}</span>
                </div>
                <div v-if="test.multiRegionConfig.executionMode" class="info-item">
                  <span class="info-label">Execution Mode</span>
                  <span class="info-value">{{ test.multiRegionConfig.executionMode }}</span>
                </div>
                <div v-if="test.multiRegionConfig.timeout" class="info-item">
                  <span class="info-label">Timeout</span>
                  <span class="info-value">{{ test.multiRegionConfig.timeout }}ms</span>
                </div>
                <div v-if="test.multiRegionConfig.user?.id" class="info-item">
                  <span class="info-label">User ID</span>
                  <span class="info-value">{{ test.multiRegionConfig.user.id }}</span>
                </div>
                <div v-if="test.multiRegionConfig.resource?.id" class="info-item">
                  <span class="info-label">Resource ID</span>
                  <span class="info-value">{{ test.multiRegionConfig.resource.id }}</span>
                </div>
                <div v-if="test.multiRegionConfig.action" class="info-item">
                  <span class="info-label">Action</span>
                  <span class="info-value">{{ test.multiRegionConfig.action }}</span>
                </div>
                <div v-if="test.multiRegionConfig.expectedResult !== undefined" class="info-item">
                  <span class="info-label">Expected Result</span>
                  <span class="info-value" :class="test.multiRegionConfig.expectedResult ? 'allowed' : 'denied'">
                    {{ test.multiRegionConfig.expectedResult ? 'Allow' : 'Deny' }}
                  </span>
                </div>
              </div>

              <!-- Policy Consistency Config -->
              <div v-if="test.distributedTestType === 'policy-consistency' && test.policyConsistencyConfig" class="config-section">
                <h4 class="config-section-title">Policy Consistency Configuration</h4>
                <div v-if="test.policyConsistencyConfig.regions" class="info-item">
                  <span class="info-label">Regions</span>
                  <span class="info-value">{{ test.policyConsistencyConfig.regions.join(', ') }}</span>
                </div>
                <div v-if="test.policyConsistencyConfig.checkTypes" class="info-item">
                  <span class="info-label">Check Types</span>
                  <span class="info-value">{{ test.policyConsistencyConfig.checkTypes.join(', ') }}</span>
                </div>
                <div v-if="test.policyConsistencyConfig.policyIds" class="info-item">
                  <span class="info-label">Policy IDs</span>
                  <span class="info-value">{{ test.policyConsistencyConfig.policyIds.join(', ') }}</span>
                </div>
              </div>

              <!-- Policy Sync Config -->
              <div v-if="test.distributedTestType === 'policy-synchronization' && test.policySyncConfig" class="config-section">
                <h4 class="config-section-title">Policy Synchronization Configuration</h4>
                <div v-if="test.policySyncConfig.regions" class="info-item">
                  <span class="info-label">Regions</span>
                  <span class="info-value">{{ test.policySyncConfig.regions.join(', ') }}</span>
                </div>
                <div v-if="test.policySyncConfig.testScenarios" class="info-item">
                  <span class="info-label">Test Scenarios</span>
                  <span class="info-value">{{ test.policySyncConfig.testScenarios.join(', ') }}</span>
                </div>
                <div v-if="test.policySyncConfig.policyId" class="info-item">
                  <span class="info-label">Policy ID</span>
                  <span class="info-value">{{ test.policySyncConfig.policyId }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- API Security Specific Info -->
          <div v-if="test.testType === 'api-security'" class="info-card">
            <h3 class="card-title">
              <Shield class="title-icon" />
              API Security Configuration
            </h3>
            <div class="info-list">
              <div v-if="test.apiVersion" class="info-item">
                <span class="info-label">Sub-Type</span>
                <span class="info-value">API Versioning</span>
              </div>
              <div v-if="test.apiVersion" class="info-item">
                <span class="info-label">Version</span>
                <span class="info-value">{{ test.apiVersion.version }}</span>
              </div>
              <div v-if="test.apiVersion" class="info-item">
                <span class="info-label">Endpoint</span>
                <span class="info-value">{{ test.apiVersion.endpoint }}</span>
              </div>
              <div v-if="test.apiVersion && test.apiVersion.deprecated" class="info-item">
                <span class="info-label">Deprecated</span>
                <span class="info-value">Yes</span>
              </div>

              <div v-if="test.gatewayPolicy" class="info-item">
                <span class="info-label">Sub-Type</span>
                <span class="info-value">Gateway Policy</span>
              </div>
              <div v-if="test.gatewayPolicy" class="info-item">
                <span class="info-label">Gateway Type</span>
                <span class="info-value">{{ test.gatewayPolicy.gatewayType }}</span>
              </div>
              <div v-if="test.gatewayPolicy" class="info-item">
                <span class="info-label">Policy ID</span>
                <span class="info-value">{{ test.gatewayPolicy.policyId }}</span>
              </div>
              <div v-if="test.gatewayPolicy" class="info-item">
                <span class="info-label">Policy Type</span>
                <span class="info-value">{{ test.gatewayPolicy.policyType }}</span>
              </div>

              <div v-if="test.webhook" class="info-item">
                <span class="info-label">Sub-Type</span>
                <span class="info-value">Webhook Security</span>
              </div>
              <div v-if="test.webhook" class="info-item">
                <span class="info-label">Endpoint</span>
                <span class="info-value">{{ test.webhook.endpoint }}</span>
              </div>
              <div v-if="test.webhook" class="info-item">
                <span class="info-label">Authentication</span>
                <span class="info-value">{{ test.webhook.authentication?.type }} ({{ test.webhook.authentication?.method }})</span>
              </div>

              <div v-if="test.graphql" class="info-item">
                <span class="info-label">Sub-Type</span>
                <span class="info-value">GraphQL Security</span>
              </div>
              <div v-if="test.graphql" class="info-item">
                <span class="info-label">Endpoint</span>
                <span class="info-value">{{ test.graphql.endpoint }}</span>
              </div>
              <div v-if="test.graphql" class="info-item">
                <span class="info-label">Test Type</span>
                <span class="info-value">{{ test.graphql.testType }}</span>
              </div>

              <div v-if="test.apiContract" class="info-item">
                <span class="info-label">Sub-Type</span>
                <span class="info-value">API Contract</span>
              </div>
              <div v-if="test.apiContract" class="info-item">
                <span class="info-label">Contract Version</span>
                <span class="info-value">{{ test.apiContract.version }}</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Policy Section (for access-control tests) -->
        <div v-if="test.testType === 'access-control' && test.policyId" class="content-section">
          <div class="section-header">
            <h2 class="section-title">
              <Shield class="title-icon" />
              Policy Referenced
            </h2>
          </div>
          <div class="policies-list">
            <div
              class="policy-item"
              @click="viewPolicy(test.policyId)"
            >
              <div class="policy-info">
                <h4 class="policy-name">{{ getPolicyName(test.policyId) }}</h4>
                <p class="policy-type">{{ getPolicyType(test.policyId) }}</p>
              </div>
              <Eye class="view-icon" />
            </div>
          </div>
        </div>

        <!-- Cross Links -->
        <CrossLinkPanel
          v-if="test"
          entity-type="test"
          :entity-id="test.id"
        />
      </div>

      <!-- Configuration Tab -->
      <div v-if="activeTab === 'configuration'" class="tab-content">
        <div class="config-section">
          <h3 class="section-title">Test Configuration</h3>
          <pre class="config-json">{{ JSON.stringify(getTestConfiguration(test), null, 2) }}</pre>
        </div>
      </div>

      <!-- Version History Tab -->
      <div v-if="activeTab === 'versions'" class="tab-content">
        <div class="versions-section">
          <h3 class="section-title">Version History</h3>
          <div v-if="!test.versionHistory || test.versionHistory.length === 0" class="empty-state">
            <p>No version history available</p>
          </div>
          <div v-else class="versions-list">
            <div
              v-for="version in test.versionHistory"
              :key="version.version"
              class="version-item"
            >
              <div class="version-header">
                <span class="version-number">v{{ version.version }}</span>
                <span class="version-date">{{ formatDate(version.changedAt) }}</span>
              </div>
              <div v-if="version.changedBy" class="version-meta">
                Changed by: {{ version.changedBy }}
              </div>
              <div v-if="version.changeReason" class="version-reason">
                {{ version.changeReason }}
              </div>
              <div v-if="version.changes && version.changes.length > 0" class="version-changes">
                <strong>Changes:</strong>
                <ul>
                  <li v-for="change in version.changes" :key="change">{{ change }}</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import {
  Edit,
  Trash2,
  History,
  Info,
  Shield,
  List,
  Eye,
  Network,
} from 'lucide-vue-next';
import CrossLinkPanel from '../components/CrossLinkPanel.vue';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';

const router = useRouter();
const route = useRoute();

const test = ref<any>(null);
const policies = ref<any[]>([]);
const applications = ref<any[]>([]);
const suitesUsingTest = ref<any[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const activeTab = ref('overview');

const tabs = [
  { id: 'overview', label: 'Overview', icon: Info },
  { id: 'configuration', label: 'Configuration', icon: Shield },
  { id: 'versions', label: 'Version History', icon: History },
];

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests/individual' },
  { label: test.value?.name || 'Test' },
]);

const loadTest = async () => {
  loading.value = true;
  error.value = null;
  try {
    const testId = route.params.id as string;
    const [testRes, policiesRes, applicationsRes] = await Promise.all([
      axios.get(`/api/tests/${testId}`),
      axios.get('/api/policies'),
      axios.get('/api/v1/applications'),
    ]);
    test.value = testRes.data;
    policies.value = policiesRes.data;
    applications.value = applicationsRes.data || [];
    
    // Load suites using this test
    await loadSuitesUsingTest();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test';
    console.error('Error loading test:', err);
  } finally {
    loading.value = false;
  }
};

const loadSuitesUsingTest = async () => {
  if (!test.value?.id) return;
  
  try {
    const response = await axios.get('/api/v1/test-suites');
    suitesUsingTest.value = response.data.filter((suite: any) =>
      suite.testIds && suite.testIds.includes(test.value.id)
    );
  } catch (err) {
    console.error('Error loading suites:', err);
  }
};

const getTestTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
  };
  return labels[type] || type;
};

const getPolicyName = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.name || policyId;
};

const getPolicyType = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.type?.toUpperCase() || 'Unknown';
};

const getApplicationName = (applicationId: string): string => {
  const application = applications.value.find(a => a.id === applicationId);
  return application?.name || '';
};

const getDistributedTestTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    'multi-region': 'Multi-Region Test',
    'policy-consistency': 'Policy Consistency',
    'policy-synchronization': 'Policy Synchronization',
  };
  return labels[type] || type;
};

const getTestConfiguration = (test: any): any => {
  if (test.testType === 'access-control') {
    return {
      policyId: test.policyId,
      inputs: test.inputs,
      expected: test.expected,
    };
  }
  if (test.testType === 'distributed-systems') {
    return {
      distributedTestType: test.distributedTestType,
      applicationId: test.applicationId,
      multiRegionConfig: test.multiRegionConfig,
      policyConsistencyConfig: test.policyConsistencyConfig,
      policySyncConfig: test.policySyncConfig,
    };
  }
  return test;
};

const editTest = () => {
  router.push(`/tests/individual/${test.value?.id}/edit`);
};

const deleteTest = async () => {
  if (!confirm('Are you sure you want to delete this test?')) {
    return;
  }
  
  try {
    await axios.delete(`/api/tests/${test.value.id}`);
    router.push('/tests/individual');
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete test';
    console.error('Error deleting test:', err);
  }
};

const viewPolicy = (policyId: string) => {
  router.push(`/policies/${policyId}`);
};

const viewSuite = (suiteId: string) => {
  router.push(`/tests/suites/${suiteId}`);
};

const viewVersions = () => {
  activeTab.value = 'versions';
};

const handleTestSaved = () => {
  loadTest();
};

const formatDate = (date: Date | string): string => {
  if (!date) return 'Never';
  const d = new Date(date);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
};

onMounted(() => {
  loadTest();
});
</script>

<style scoped>
.test-detail-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.detail-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.header-left {
  flex: 1;
}

.test-title-row {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 0.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.version-badge {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  padding: 0.25rem 0.75rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 600;
}

.test-meta {
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.9rem;
  margin: 0 0 0.5rem 0;
}

.test-description {
  color: rgba(255, 255, 255, 0.8);
  margin: 0.5rem 0 0 0;
}

.header-actions {
  display: flex;
  gap: 0.5rem;
}

.action-btn {
  padding: 0.5rem 1rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.tabs {
  display: flex;
  gap: 0.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  margin-bottom: 2rem;
}

.tab-button {
  padding: 0.75rem 1.5rem;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: rgba(255, 255, 255, 0.6);
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.tab-button:hover {
  color: rgba(255, 255, 255, 0.8);
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  padding: 2rem 0;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.info-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.125rem;
  font-weight: 600;
  margin: 0 0 1rem 0;
  color: #ffffff;
}

.title-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.info-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
}

.info-value {
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
}

.info-value.allowed {
  color: #10b981;
}

.info-value.denied {
  color: #ef4444;
}

.config-section {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.config-section-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.content-section {
  margin-bottom: 2rem;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.policies-list,
.suites-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.policy-item,
.suite-item {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  cursor: pointer;
  transition: all 0.2s;
}

.policy-item:hover,
.suite-item:hover {
  border-color: rgba(79, 172, 254, 0.5);
}

.policy-name,
.suite-name {
  font-size: 1rem;
  font-weight: 600;
  margin: 0 0 0.25rem 0;
  color: #ffffff;
}

.policy-type,
.suite-meta {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
  margin: 0;
}

.view-icon {
  width: 20px;
  height: 20px;
  color: rgba(255, 255, 255, 0.6);
}

.config-json {
  background: rgba(15, 20, 25, 0.8);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.5rem;
  color: #ffffff;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  overflow-x: auto;
}

.versions-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.version-item {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
}

.version-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.version-number {
  font-weight: 600;
  color: #4facfe;
}

.version-date {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
}

.version-meta,
.version-reason {
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.875rem;
  margin: 0.5rem 0;
}

.version-changes {
  margin-top: 0.5rem;
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.875rem;
}

.version-changes ul {
  margin: 0.5rem 0 0 1.5rem;
  padding: 0;
}

.loading,
.error {
  text-align: center;
  padding: 4rem 2rem;
  color: rgba(255, 255, 255, 0.7);
}

.empty-state {
  text-align: center;
  padding: 2rem;
  color: rgba(255, 255, 255, 0.6);
}
</style>

