<template>
  <div class="policy-detail-page">
    <div v-if="loading" class="loading">Loading policy...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && policy" class="policy-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <div class="policy-title-row">
              <h1 class="page-title">{{ policy.name }}</h1>
              <span class="policy-status" :class="`status-${policy.status}`">
                {{ policy.status }}
              </span>
            </div>
            <p class="policy-meta">
              {{ policy.type.toUpperCase() }} • v{{ policy.version }}
            </p>
            <p class="policy-description">{{ policy.description }}</p>
          </div>
          <div class="header-actions">
            <button @click="editPolicy" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="testPolicy" class="action-btn test-btn">
              <TestTube class="action-icon" />
              Test
            </button>
            <button @click="viewVersions" class="action-btn view-btn">
              <History class="action-icon" />
              Versions
            </button>
            <button @click="deployPolicy()" class="action-btn deploy-btn">
              <Upload class="action-icon" />
              Deploy
            </button>
            <button @click="showAuditLog = true; loadAuditLogs()" class="action-btn audit-btn">
              <FileText class="action-icon" />
              Audit Log
            </button>
          </div>
        </div>
      </div>

      <!-- Overview Section -->
      <div class="content-section">
        <div class="overview-grid">
          <div class="info-card">
            <h3 class="card-title">
              <Info class="title-icon" />
              Policy Information
            </h3>
            <div class="info-list">
              <div class="info-item">
                <span class="info-label">Type</span>
                <span class="info-value">{{ policy.type.toUpperCase() }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Version</span>
                <span class="info-value">{{ policy.version }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Status</span>
                <span class="info-value status-badge" :class="`status-${policy.status}`">
                  {{ policy.status }}
                </span>
              </div>
              <div class="info-item">
                <span class="info-label">Created</span>
                <span class="info-value">{{ formatDate(policy.createdAt) }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Last Updated</span>
                <span class="info-value">{{ formatDate(policy.lastUpdated) }}</span>
              </div>
              <div v-if="policy.type === 'abac'" class="info-item">
                <span class="info-label">Effect</span>
                <span class="info-value">{{ policy.effect }}</span>
              </div>
              <div v-if="policy.type === 'abac'" class="info-item">
                <span class="info-label">Priority</span>
                <span class="info-value">{{ policy.priority }}</span>
              </div>
            </div>
          </div>

          <div class="stats-card">
            <h3 class="card-title">
              <BarChart3 class="title-icon" />
              Statistics
            </h3>
            <div class="stats-list">
              <div class="stat-item">
                <span class="stat-label">Total Rules/Conditions</span>
                <span class="stat-value">{{ policy.ruleCount }}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Test Coverage</span>
                <span class="stat-value">{{ policy.testCoverage || 'N/A' }}</span>
              </div>
              <div class="stat-item">
                <span class="stat-label">Violations Detected</span>
                <span class="stat-value">{{ policy.violationsDetected || 0 }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tests Using This Policy Section -->
      <div class="content-section">
        <div class="section-header">
          <h2 class="section-title">
            <TestTube class="title-icon" />
            Tests Using This Policy
          </h2>
          <div class="section-actions">
            <button @click="createTestFromPolicy" class="btn-small btn-primary">
              <Plus class="btn-icon-small" />
              Create Test
            </button>
            <button @click="viewAllTests" class="btn-small btn-secondary">
              View All Tests
            </button>
          </div>
        </div>
        <div v-if="loadingTests" class="loading">Loading tests...</div>
        <div v-else-if="testsUsingPolicy.length === 0" class="empty-tests">
          <TestTube class="empty-icon" />
          <p>No tests are currently using this policy</p>
          <button @click="createTestFromPolicy" class="btn-primary">
            <Plus class="btn-icon" />
            Create Test from Policy
          </button>
        </div>
        <div v-else class="tests-list">
          <div
            v-for="test in testsUsingPolicy"
            :key="test.id"
            class="test-item"
            @click="viewTest(test.id)"
          >
            <div class="test-info">
              <div class="test-name-row">
                <h4 class="test-name">{{ test.name }}</h4>
                <span class="version-badge">v{{ test.version }}</span>
              </div>
              <p v-if="test.description" class="test-description">{{ test.description }}</p>
              <div class="test-meta">
                <span class="meta-item">
                  <span class="meta-label">Role:</span>
                  <span class="meta-value">{{ test.role }}</span>
                </span>
                <span class="meta-item">
                  <span class="meta-label">Resource:</span>
                  <span class="meta-value">{{ test.resource?.type || test.resource?.id }}</span>
                </span>
                <span class="meta-item">
                  <span class="meta-label">Expected:</span>
                  <span class="meta-value" :class="test.expectedDecision ? 'allowed' : 'denied'">
                    {{ test.expectedDecision ? 'Allow' : 'Deny' }}
                  </span>
                </span>
              </div>
            </div>
            <div class="test-actions">
              <button @click.stop="viewTest(test.id)" class="action-btn view-btn">
                <Eye class="action-icon" />
                View
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Validator Information Section -->
      <div class="content-section" v-if="validatorsUsingPolicy.length > 0">
        <div class="section-header">
          <h2 class="section-title">
            <TestTube class="title-icon" />
            Validators Using This Policy
          </h2>
          <span class="validator-count">{{ validatorsUsingPolicy.length }} validator{{ validatorsUsingPolicy.length !== 1 ? 's' : '' }}</span>
        </div>
        <div class="validators-list">
          <div
            v-for="validator in validatorsUsingPolicy"
            :key="validator.id"
            class="validator-item"
            @click="viewValidator(validator.id)"
          >
            <div class="validator-info">
              <h4 class="validator-name">{{ validator.name }}</h4>
              <p class="validator-description">{{ validator.description }}</p>
              <div class="validator-meta">
                <span class="meta-item">
                  <span class="meta-label">Type:</span>
                  <span class="meta-value">{{ validator.testType }}</span>
                </span>
                <span class="meta-item">
                  <span class="meta-label">Version:</span>
                  <span class="meta-value">{{ validator.version }}</span>
                </span>
                <span class="meta-item">
                  <span class="meta-label">Status:</span>
                  <span class="meta-value" :class="validator.enabled ? 'status-enabled' : 'status-disabled'">
                    {{ validator.enabled ? 'Enabled' : 'Disabled' }}
                  </span>
                </span>
              </div>
            </div>
            <div class="validator-actions">
              <button @click.stop="viewValidator(validator.id)" class="action-btn view-btn">
                <Eye class="action-icon" />
                View Details
              </button>
            </div>
          </div>
        </div>
        <div v-if="validatorsUsingPolicy.length === 0" class="empty-validators">
          <TestTube class="empty-icon" />
          <p>No validators are currently using this policy</p>
        </div>
      </div>

      <!-- Rules/Conditions Section -->
      <div class="content-section">
        <!-- RBAC Rules -->
        <div v-if="policy.type === 'rbac'">
          <div class="section-header">
            <h2 class="section-title">
              <Shield class="title-icon" />
              Policy Rules
            </h2>
            <span class="rule-count">{{ policy.rules?.length || 0 }} rules</span>
          </div>
          <div class="rules-list">
            <div
              v-for="(rule, index) in policy.rules"
              :key="rule.id || index"
              class="rule-card"
            >
              <div class="rule-header">
                <div class="rule-title-group">
                  <h3 class="rule-name">{{ rule.id }}</h3>
                  <span class="rule-effect" :class="`effect-${rule.effect}`">
                    {{ rule.effect }}
                  </span>
                </div>
              </div>
              <p class="rule-description">{{ rule.description }}</p>
              <div class="rule-conditions">
                <h4 class="conditions-title">Conditions</h4>
                <div class="conditions-grid">
                  <div
                    v-for="(value, key) in rule.conditions"
                    :key="key"
                    class="condition-display"
                  >
                    <span class="condition-key">{{ key }}</span>
                    <span class="condition-separator">:</span>
                    <span class="condition-value">
                      {{ Array.isArray(value) ? JSON.stringify(value) : value }}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- ABAC Conditions -->
        <div v-if="policy.type === 'abac'">
          <div class="section-header">
            <h2 class="section-title">
              <Shield class="title-icon" />
              Policy Conditions
            </h2>
            <span class="rule-count">{{ policy.conditions?.length || 0 }} conditions</span>
          </div>
          <div class="conditions-list">
            <div
              v-for="(condition, index) in policy.conditions"
              :key="index"
              class="condition-card"
            >
              <div class="condition-header">
                <h3 class="condition-title">Condition {{ index + 1 }}</h3>
                <span v-if="condition.logicalOperator" class="logical-operator">
                  {{ condition.logicalOperator }}
                </span>
              </div>
              <div class="condition-details">
                <div class="detail-row">
                  <span class="detail-label">Attribute:</span>
                  <span class="detail-value">{{ condition.attribute }}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Operator:</span>
                  <span class="detail-value">{{ condition.operator }}</span>
                </div>
                <div class="detail-row">
                  <span class="detail-label">Value:</span>
                  <span class="detail-value">{{ condition.value }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- JSON Section -->
      <div class="content-section">
        <div class="json-viewer">
          <div class="viewer-header">
            <h2 class="section-title">
              <FileCode class="title-icon" />
              Policy JSON
            </h2>
            <button @click="copyJSON" class="btn-copy">
              <Copy class="btn-icon" />
              Copy
            </button>
          </div>
          <pre class="json-content">{{ JSON.stringify(policyJSON, null, 2) }}</pre>
        </div>
      </div>

      <!-- Changelog Section -->
      <div class="content-section">
        <div class="changelog-section">
          <div class="section-header">
            <h2 class="section-title">
              <History class="title-icon" />
              Version History
            </h2>
            <button @click="showVersionModal = true" class="btn-add-version">
              <Plus class="btn-icon" />
              Add Version
            </button>
          </div>
          <div class="changelog-timeline">
            <div
              v-for="(version, index) in policy.versions"
              :key="version.version"
              class="version-item"
            >
              <div class="version-marker" :class="`version-${version.status}`">
                <div class="marker-dot"></div>
                <div v-if="index < policy.versions.length - 1" class="marker-line"></div>
              </div>
              <div class="version-content">
                <div class="version-header">
                  <div class="version-title-row">
                    <h3 class="version-title">Version {{ version.version }}</h3>
                    <span class="version-status" :class="`status-${version.status}`">
                      {{ version.status }}
                    </span>
                  </div>
                  <span class="version-date">{{ formatDateTime(version.date) }}</span>
                </div>
                <div class="version-changes">
                  <h4 class="changes-title">Changes</h4>
                  <ul class="changes-list">
                    <li v-for="(change, changeIndex) in version.changes" :key="changeIndex">
                      <span class="change-type" :class="`change-${change.type}`">
                        {{ change.type }}
                      </span>
                      {{ change.description }}
                    </li>
                  </ul>
                </div>
                <div v-if="version.author" class="version-author">
                  <User class="author-icon" />
                  <span>{{ version.author }}</span>
                </div>
                <div v-if="version.notes" class="version-notes">
                  <p>{{ version.notes }}</p>
                </div>
              </div>
            </div>
          </div>
          <div v-if="policy.versions.length === 0" class="empty-state">
            <History class="empty-icon" />
            <h3>No version history</h3>
            <p>Version history will appear here as the policy is updated</p>
          </div>
        </div>
      </div>

    </div>

    <!-- Add Version Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showVersionModal" class="modal-overlay" @click="closeVersionModal">
          <div class="modal-content version-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Plus class="modal-title-icon" />
                <h2>Add New Version</h2>
              </div>
              <button @click="closeVersionModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="addVersion" class="version-form">
                <div class="form-group">
                  <label>Version Number</label>
                  <input v-model="versionForm.version" type="text" required placeholder="e.g., 1.1.0" />
                </div>
                <div class="form-group">
                  <label>Status</label>
                  <Dropdown
                    v-model="versionForm.status"
                    :options="versionStatusOptions"
                    placeholder="Select status..."
                  />
                </div>
                <div class="form-group">
                  <label>Changes</label>
                  <div class="changes-editor">
                    <div
                      v-for="(change, index) in versionForm.changes"
                      :key="index"
                      class="change-item"
                    >
                      <Dropdown
                        v-model="change.type"
                        :options="changeTypeOptions"
                        placeholder="Change type..."
                        class="change-type-select"
                      />
                      <input
                        v-model="change.description"
                        type="text"
                        placeholder="Describe the change..."
                        class="change-description"
                      />
                      <button
                        type="button"
                        @click="removeChange(index)"
                        class="btn-remove-small"
                      >
                        <X class="icon" />
                      </button>
                    </div>
                    <button type="button" @click="addChange" class="btn-add-change">
                      <Plus class="icon" />
                      Add Change
                    </button>
                  </div>
                </div>
                <div class="form-group">
                  <label>Notes (Optional)</label>
                  <textarea v-model="versionForm.notes" rows="3" placeholder="Additional notes about this version..."></textarea>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeVersionModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">Add Version</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Test Policy Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showTestModal" class="modal-overlay" @click="showTestModal = false">
          <div class="modal-content test-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <TestTube class="modal-title-icon" />
                <h2>Test Policy</h2>
              </div>
              <button @click="showTestModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="form-group">
                <label>Test Data (JSON)</label>
                <textarea 
                  :value="JSON.stringify(testData, null, 2)" 
                  rows="10"
                  @input="try { testData = JSON.parse(($event.target as HTMLTextAreaElement).value); } catch(e) {}"
                ></textarea>
              </div>
              <button @click="runTest" class="btn-primary">Run Test</button>
              <div v-if="testResult" class="test-result">
                <h3>Test Result</h3>
                <pre>{{ JSON.stringify(testResult, null, 2) }}</pre>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Audit Log Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAuditLog" class="modal-overlay" @click="showAuditLog = false">
          <div class="modal-content audit-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <FileText class="modal-title-icon" />
                <h2>Audit Log</h2>
              </div>
              <button @click="showAuditLog = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="audit-log-list">
                <div v-for="log in auditLogs" :key="log.id" class="audit-log-item">
                  <div class="log-header">
                    <span class="log-action">{{ log.action }}</span>
                    <span class="log-date">{{ formatDateTime(log.timestamp) }}</span>
                  </div>
                  <div v-if="log.details" class="log-details">
                    <pre>{{ JSON.stringify(log.details, null, 2) }}</pre>
                  </div>
                </div>
                <div v-if="auditLogs.length === 0" class="empty-state">
                  <p>No audit logs found</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Version Comparison Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showComparisonModal" class="modal-overlay" @click="showComparisonModal = false">
          <div class="modal-content comparison-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <History class="modal-title-icon" />
                <h2>Compare Versions</h2>
              </div>
              <button @click="showComparisonModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="form-group">
                <label>Version 1</label>
                <Dropdown
                  v-model="comparisonVersions.version1"
                  :options="versionOptions"
                  placeholder="Select version..."
                />
              </div>
              <div class="form-group">
                <label>Version 2</label>
                <Dropdown
                  v-model="comparisonVersions.version2"
                  :options="versionOptions"
                  placeholder="Select version..."
                />
              </div>
              <button @click="compareVersions" class="btn-primary">Compare</button>
              <div v-if="comparisonResult" class="comparison-result">
                <h3>Differences</h3>
                <pre>{{ JSON.stringify(comparisonResult.differences, null, 2) }}</pre>
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
import { useRoute, useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  Edit,
  TestTube,
  History,
  Plus,
  X,
  User,
  Copy,
  Info,
  BarChart3,
  FileCode,
  Shield,
  Eye,
  Upload,
  FileText
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const route = useRoute();
const router = useRouter();

const policyId = computed(() => route.params.id as string);
const loading = ref(true);
const error = ref<string | null>(null);
const showVersionModal = ref(false);

const policy = ref<any>(null);
const validators = ref<any[]>([]);
const testsUsingPolicy = ref<any[]>([]);
const loadingTests = ref(false);

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: policy.value?.name || 'Policy' }
]);

const validatorsUsingPolicy = computed(() => {
  if (!policy.value || validators.value.length === 0) return [];
  
  // In a real implementation, this would check which validators reference this policy
  // For now, we'll match validators that have the same test type as the policy type
  // or validators that explicitly reference this policy in their config
  return validators.value.filter(validator => {
    // Match by test type (e.g., access-control validators use RBAC policies)
    if (policy.value.type === 'rbac' && validator.testType === 'access-control') {
      return true;
    }
    if (policy.value.type === 'abac' && validator.testType === 'access-control') {
      return true;
    }
    // Check if validator config references this policy
    if (validator.config?.policyId === policy.value.id) {
      return true;
    }
    if (validator.config?.policies?.includes(policy.value.id)) {
      return true;
    }
    return false;
  });
});

const versionForm = ref({
  version: '',
  status: 'draft',
  changes: [{ type: 'added', description: '' }],
  notes: ''
});

const versionStatusOptions = computed(() => [
  { label: 'Draft', value: 'draft' },
  { label: 'Active', value: 'active' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const changeTypeOptions = computed(() => [
  { label: 'Added', value: 'added' },
  { label: 'Changed', value: 'changed' },
  { label: 'Fixed', value: 'fixed' },
  { label: 'Removed', value: 'removed' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data;
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

const viewValidator = (validatorId: string) => {
  router.push(`/admin?tab=validators&validator=${validatorId}`);
};

const loadPolicy = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get(`/api/policies/${policyId.value}`);
    policy.value = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      lastUpdated: new Date(response.data.updatedAt),
      ruleCount: response.data.ruleCount || (response.data.type === 'rbac' 
        ? (response.data.rules?.length || 0) 
        : (response.data.conditions?.length || 0)),
      versions: (response.data.versions || []).map((v: any) => ({
        ...v,
        date: new Date(v.date)
      }))
    };
  } catch (err: any) {
    error.value = err.message || 'Failed to load policy';
  } finally {
    loading.value = false;
  }
};

const policyJSON = computed(() => {
  if (!policy.value) return {};
  
  if (policy.value.type === 'rbac') {
    return {
      name: policy.value.name,
      version: policy.value.version,
      rules: policy.value.rules
    };
  } else {
    return {
      id: policy.value.id,
      name: policy.value.name,
      description: policy.value.description,
      effect: policy.value.effect,
      priority: policy.value.priority,
      conditions: policy.value.conditions
    };
  }
});

const editPolicy = () => {
  router.push(`/policies/edit/${policyId.value}`);
};

const testPolicy = async () => {
  // Open test modal or navigate to test page
  showTestModal.value = true;
};

const showTestModal = ref(false);
const testData = ref({
  subject: { role: 'admin', department: 'engineering' },
  resource: { id: 'resource-1', sensitivity: 'internal' },
  action: 'read'
});

const runTest = async () => {
  try {
    loading.value = true;
    const response = await axios.post(`/api/policies/${policyId.value}/test`, testData.value);
    testResult.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to test policy';
  } finally {
    loading.value = false;
  }
};

const testResult = ref<any>(null);


const addChange = () => {
  versionForm.value.changes.push({ type: 'added', description: '' });
};

const removeChange = (index: number) => {
  versionForm.value.changes.splice(index, 1);
};

const addVersion = async () => {
  if (!policy.value) return;
  
  try {
    loading.value = true;
    const newVersion = {
      version: versionForm.value.version,
      status: versionForm.value.status,
      date: new Date(),
      author: 'current-user@example.com', // In real app, get from auth
      changes: versionForm.value.changes.filter(c => c.description),
      notes: versionForm.value.notes
    };
    
    await axios.post(`/api/policies/${policyId.value}/versions`, newVersion);
    await loadPolicy();
    closeVersionModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to add version';
  } finally {
    loading.value = false;
  }
};

const deployPolicy = async (version?: string) => {
  if (!confirm(`Deploy version ${version || policy.value?.version}?`)) {
    return;
  }
  
  try {
    loading.value = true;
    await axios.post(`/api/policies/${policyId.value}/deploy`, { version });
    await loadPolicy();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to deploy policy';
  } finally {
    loading.value = false;
  }
};

const rollbackPolicy = async (targetVersion: string) => {
  if (!confirm(`Rollback to version ${targetVersion}?`)) {
    return;
  }
  
  try {
    loading.value = true;
    await axios.post(`/api/policies/${policyId.value}/rollback`, { version: targetVersion });
    await loadPolicy();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to rollback policy';
  } finally {
    loading.value = false;
  }
};

const showComparisonModal = ref(false);
const comparisonVersions = ref({ version1: '', version2: '' });
const comparisonResult = ref<any>(null);

const viewVersions = () => {
  showComparisonModal.value = true;
};

const versionOptions = computed(() => {
  if (!policy.value) return [];
  return policy.value.versions.map((v: any) => ({
    label: `v${v.version} (${v.status})`,
    value: v.version
  }));
});

const compareVersions = async () => {
  if (!comparisonVersions.value.version1 || !comparisonVersions.value.version2) {
    return;
  }
  
  try {
    loading.value = true;
    const response = await axios.get(
      `/api/policies/${policyId.value}/compare/${comparisonVersions.value.version1}/${comparisonVersions.value.version2}`
    );
    comparisonResult.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to compare versions';
  } finally {
    loading.value = false;
  }
};

const auditLogs = ref<any[]>([]);
const showAuditLog = ref(false);

const loadAuditLogs = async () => {
  try {
    const response = await axios.get(`/api/policies/${policyId.value}/audit`);
    auditLogs.value = response.data.map((log: any) => ({
      ...log,
      timestamp: new Date(log.timestamp)
    }));
  } catch (err: any) {
    console.error('Error loading audit logs:', err);
  }
};

const closeVersionModal = () => {
  showVersionModal.value = false;
  versionForm.value = {
    version: '',
    status: 'draft',
    changes: [{ type: 'added', description: '' }],
    notes: ''
  };
};

const copyJSON = async () => {
  try {
    await navigator.clipboard.writeText(JSON.stringify(policyJSON.value, null, 2));
    // Show toast notification (in real app)
    alert('JSON copied to clipboard!');
  } catch (err) {
    console.error('Failed to copy:', err);
  }
};

const formatDate = (date: Date): string => {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });
};

const formatDateTime = (date: Date): string => {
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  });
};

const loadTestsUsingPolicy = async () => {
  if (!policyId.value) return;
  
  loadingTests.value = true;
  try {
    const response = await axios.get(`/api/policies/${policyId.value}/tests`);
    testsUsingPolicy.value = response.data;
  } catch (err: any) {
    console.error('Error loading tests:', err);
  } finally {
    loadingTests.value = false;
  }
};

const viewTest = (testId: string) => {
  router.push(`/tests/test/${testId}`);
};

const viewAllTests = () => {
  router.push(`/tests/individual?policyId=${policyId.value}`);
};

const createTestFromPolicy = () => {
  router.push({
    path: '/tests/individual',
    query: { createFromPolicy: policyId.value },
  });
};

onMounted(() => {
  loadPolicy();
  loadValidators();
  loadTestsUsingPolicy();
});
</script>

<style scoped>
.policy-detail-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.detail-header {
  margin-bottom: 32px;
}


.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  flex-wrap: wrap;
}

.header-left {
  flex: 1;
}

.policy-title-row {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 8px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0;
}

.policy-status {
  padding: 6px 14px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-draft {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-deprecated {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.policy-meta {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 12px;
}

.policy-description {
  font-size: 1.1rem;
  color: #a0aec0;
  line-height: 1.6;
  max-width: 800px;
}

.header-actions {
  display: flex;
  gap: 12px;
  flex-shrink: 0;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.edit-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.test-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.view-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-icon {
  width: 18px;
  height: 18px;
}

.content-section {
  margin-bottom: 48px;
}

.content-section:last-child {
  margin-bottom: 0;
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
}

.info-card,
.stats-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
  padding-bottom: 12px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  align-items: center;
  gap: 10px;
}

.title-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  flex-shrink: 0;
}

.info-list,
.stats-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.info-item,
.stat-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label,
.stat-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value,
.stat-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  display: flex;
  align-items: center;
  gap: 12px;
}

.rule-count {
  font-size: 0.875rem;
  color: #a0aec0;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 8px;
}

.rules-list,
.conditions-list {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.rule-card,
.condition-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.rule-header,
.condition-header {
  margin-bottom: 12px;
}

.rule-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.rule-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.rule-effect {
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.effect-allow {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.effect-deny {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.rule-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin-bottom: 16px;
  line-height: 1.5;
}

.rule-conditions {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.conditions-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #718096;
  margin-bottom: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.conditions-grid {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.condition-display {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
  font-size: 0.875rem;
}

.condition-key {
  color: #4facfe;
  font-weight: 500;
}

.condition-separator {
  color: #718096;
}

.condition-value {
  color: #ffffff;
  font-family: 'Courier New', monospace;
}

.condition-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.logical-operator {
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #4facfe;
}

.condition-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 12px;
}

.detail-row {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
  min-width: 80px;
}

.detail-value {
  color: #ffffff;
  font-family: 'Courier New', monospace;
}

.changelog-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
}

.btn-add-version {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-add-version:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.changelog-timeline {
  position: relative;
  padding-left: 40px;
  margin-top: 32px;
}

.version-item {
  position: relative;
  margin-bottom: 32px;
}

.version-marker {
  position: absolute;
  left: -32px;
  top: 0;
  width: 24px;
  height: 24px;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.marker-dot {
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 3px solid;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  z-index: 2;
}

.marker-line {
  width: 2px;
  flex: 1;
  background: rgba(79, 172, 254, 0.2);
  margin-top: 4px;
}

.version-active .marker-dot {
  border-color: #22c55e;
}

.version-draft .marker-dot {
  border-color: #fbbf24;
}

.version-deprecated .marker-dot {
  border-color: #9ca3af;
}

.version-content {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.version-header {
  margin-bottom: 16px;
}

.version-title-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.version-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.version-status {
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.version-date {
  font-size: 0.875rem;
  color: #718096;
}

.version-changes {
  margin-bottom: 16px;
}

.changes-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #718096;
  margin-bottom: 12px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.changes-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.changes-list li {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.9rem;
  color: #a0aec0;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
}

.change-type {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  flex-shrink: 0;
}

.change-added {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.change-changed {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.change-fixed {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.change-removed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.change-deprecated {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.version-author {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  color: #718096;
  margin-bottom: 12px;
}

.author-icon {
  width: 16px;
  height: 16px;
}

.version-notes {
  padding: 12px;
  background: rgba(79, 172, 254, 0.05);
  border-left: 3px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  margin-top: 12px;
}

.version-notes p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.5;
}

.json-viewer {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.viewer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.btn-copy {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-copy:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.json-content {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
  overflow-x: auto;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  color: #a0aec0;
  line-height: 1.6;
  margin: 0;
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

.version-modal {
  max-width: 700px;
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

.version-form {
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
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.changes-editor {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.change-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.change-type-select {
  min-width: 120px;
  flex-shrink: 0;
}

.change-description {
  flex: 1;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
}

.change-description:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.btn-remove-small {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  color: #fc8181;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.btn-remove-small:hover {
  background: rgba(252, 129, 129, 0.1);
}

.btn-remove-small .icon {
  width: 14px;
  height: 14px;
}

.btn-add-change {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 12px;
  background: transparent;
  border: 1px dashed rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
  width: 100%;
  justify-content: center;
}

.btn-add-change:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-add-change .icon {
  width: 14px;
  height: 14px;
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

.btn-primary {
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.loading {
  text-align: center;
  padding: 50px;
  color: #4facfe;
  font-size: 1.2em;
}

.error {
  text-align: center;
  padding: 20px;
  color: #fc8181;
  font-size: 1.2em;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin: 20px auto;
  max-width: 600px;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

/* Validator Section Styles */
.validator-count {
  padding: 4px 12px;
  border-radius: 8px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 600;
}

.validators-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.validator-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s;
}

.validator-item:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
  transform: translateX(4px);
}

.validator-info {
  flex: 1;
}

.validator-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.validator-description {
  font-size: 0.9rem;
  color: #a0aec0;
  margin: 0 0 12px 0;
  line-height: 1.5;
}

.validator-meta {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}

.meta-item {
  display: flex;
  gap: 6px;
  font-size: 0.875rem;
}

.meta-label {
  color: #718096;
}

.meta-value {
  color: #ffffff;
  font-weight: 500;
}

.meta-value.status-enabled {
  color: #22c55e;
}

.meta-value.status-disabled {
  color: #9ca3af;
}

.validator-actions {
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
  background: rgba(79, 172, 254, 0.1);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-validators {
  text-align: center;
  padding: 60px 40px;
}

.empty-validators .empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.empty-validators p {
  color: #a0aec0;
  font-size: 0.9rem;
}
</style>

