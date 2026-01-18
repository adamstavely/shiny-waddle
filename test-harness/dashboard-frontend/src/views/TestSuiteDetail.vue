<template>
  <div class="test-suite-detail-page">
    <div v-if="loading" class="loading">Loading test suite...</div>
    <div v-if="error" class="error">{{ error }}</div>
    <div v-if="!loading && !error && (suite || isCreating)" class="test-suite-detail">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <div class="suite-title-row">
              <h1 class="page-title">{{ isCreating ? 'Create Test Suite' : suite.name }}</h1>
              <div v-if="!isCreating" class="suite-badges">
                <span 
                  v-if="suite.sourceType"
                  class="source-type-badge"
                  :class="suite.sourceType === 'typescript' ? 'typescript' : 'json'"
                  :title="suite.sourceType === 'typescript' ? 'TypeScript source file' : 'JSON configuration'"
                >
                  {{ suite.sourceType === 'typescript' ? 'TS' : 'JSON' }}
                </span>
                <span class="suite-status" :class="`status-${suite.status}`">
                  {{ suite.status }}
                </span>
                <span 
                  class="enabled-badge"
                  :class="suite.enabled ? 'enabled' : 'disabled'"
                >
                  {{ suite.enabled ? 'Enabled' : 'Disabled' }}
                </span>
              </div>
            </div>
            <p v-if="!isCreating" class="suite-meta">
              {{ suite.application || suite.applicationId }} • {{ suite.team }}
              <span v-if="suite.sourcePath" class="source-path">
                • {{ suite.sourcePath }}
              </span>
            </p>
            <p v-if="!isCreating && suite.description" class="suite-description">{{ suite.description }}</p>
          </div>
          <div class="header-actions">
            <button @click="saveSuite" class="action-btn save-btn" :disabled="saving">
              <Save class="action-icon" />
              {{ saving ? 'Saving...' : 'Save' }}
            </button>
            <button v-if="!isCreating" @click="runSuite" class="action-btn run-btn">
              <Play class="action-icon" />
              Run
            </button>
            <button @click="goBack" class="action-btn cancel-btn">
              <ArrowLeft class="action-icon" />
              Back
            </button>
          </div>
        </div>
      </div>

      <!-- Creation Guide Banner -->
      <div v-if="isCreating" class="creation-guide">
        <div class="guide-content">
          <Info class="guide-icon" />
          <div class="guide-text">
            <h3>Creating a Test Suite</h3>
            <p><strong>How it works:</strong> Test Suites are collections of pre-made tests. Create individual tests first, then assign them to this suite.</p>
            <ol class="guide-steps">
              <li>Enter basic information (name, application, team, test type)</li>
              <li>Go to the Tests tab to assign existing tests to this suite</li>
              <li>All tests must match the suite's test type</li>
              <li>Save your test suite</li>
            </ol>
          </div>
        </div>
      </div>

      <!-- Tabs (only show when editing existing suite) -->
      <div v-if="!isCreating" class="tabs-container">
        <div class="tabs">
          <button
            v-for="tab in visibleTabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            class="tab-button"
            :class="{ active: activeTab === tab.id }"
          >
            <component :is="tab.icon" class="tab-icon" />
            {{ tab.label }}
          </button>
        </div>
      </div>

      <!-- Tab Content -->
      <div class="tab-content-container" :class="{ 'creation-layout': isCreating }">
        <!-- Overview Tab (only for existing suites) -->
        <div v-if="!isCreating && activeTab === 'overview'" class="tab-content">
          <div class="overview-grid">
            <div class="info-card">
              <h3 class="card-title">
                <Info class="title-icon" />
                Suite Information
              </h3>
              <div class="info-list">
                <div class="info-item">
                  <span class="info-label">Name</span>
                  <span class="info-value">{{ suite.name }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Application</span>
                  <span class="info-value">{{ suite.application || suite.applicationId }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Team</span>
                  <span class="info-value">{{ suite.team }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Status</span>
                  <span class="info-value status-badge" :class="`status-${suite.status}`">
                    {{ suite.status }}
                  </span>
                </div>
                <div class="info-item">
                  <span class="info-label">Source Type</span>
                  <span class="info-value">{{ suite.sourceType || 'json' }}</span>
                </div>
                <div v-if="suite.sourcePath" class="info-item">
                  <span class="info-label">Source Path</span>
                  <span class="info-value source-path-value">{{ suite.sourcePath }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Created</span>
                  <span class="info-value">{{ formatDate(suite.createdAt) }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Last Updated</span>
                  <span class="info-value">{{ formatDate(suite.updatedAt) }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Last Run</span>
                  <span class="info-value">{{ formatDate(suite.lastRun) }}</span>
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
                  <span class="stat-label">Test Count</span>
                  <span class="stat-value">{{ suite.testCount || 0 }}</span>
                </div>
                <div class="stat-item">
                  <span class="stat-label">Score</span>
                  <span class="stat-value score" :class="getScoreClass(suite.score)">
                    {{ suite.score || 0 }}%
                  </span>
                </div>
                <div class="stat-item">
                  <span class="stat-label">Test Types</span>
                  <span class="stat-value">{{ suite.testTypes?.length || 0 }}</span>
                </div>
              </div>
              <div v-if="suite.testTypes && suite.testTypes.length > 0" class="test-types-list">
                <span
                  v-for="type in suite.testTypes"
                  :key="type"
                  class="test-type-badge"
                >
                  {{ type }}
                </span>
              </div>
            </div>
          </div>
          
          <!-- Cross Links -->
          <CrossLinkPanel
            v-if="suite"
            entity-type="test-suite"
            :entity-id="suite.id"
          />
        </div>

        <!-- Configuration Tab (show always when creating, or when tab is active when editing) -->
        <div v-if="isCreating || activeTab === 'configuration'" class="tab-content" :class="{ 'single-page-section': isCreating }">
          <div class="form-section">
            <div class="section-header">
              <h2 class="section-title">Basic Configuration</h2>
            </div>
            <div class="form-grid">
              <div class="form-group">
                <label>Test Suite Name *</label>
                <input v-model="form.name" type="text" required class="form-input" />
              </div>
              <div class="form-group">
                <label>Application *</label>
                <input v-model="form.application" type="text" required class="form-input" />
              </div>
              <div class="form-group">
                <label>Team *</label>
                <input v-model="form.team" type="text" required class="form-input" />
              </div>
            </div>

            <div class="section-header">
              <h2 class="section-title">Test Type</h2>
            </div>
            <div class="form-group">
              <label>Test Type *</label>
              <select v-model="form.testType" required class="form-input form-select">
                <option value="">Select a test type...</option>
                <option value="access-control">Access Control</option>
                <option value="network-policy">Network Policy</option>
                <option value="dlp">Data Loss Prevention (DLP)</option>
                <option value="distributed-systems">Distributed Systems</option>
                <option value="api-security">API Security</option>
                <option value="data-pipeline">Data Pipeline</option>
              </select>
              <small class="text-muted text-xs mt-xs" style="display: block;">
                Each test suite must have exactly one test type. All tests in this suite will be of the selected type.
              </small>
              <div v-if="form.testType" class="test-type-info">
                <p><strong>Selected:</strong> {{ getTestTypeLabel(form.testType) }}</p>
                <p class="test-generation-note">
                  <Info class="info-icon-small" />
                  All tests assigned to this suite must be of type: <strong>{{ getTestTypeLabel(form.testType) }}</strong>
                </p>
              </div>
            </div>
            <div class="form-group">
              <label>Description</label>
              <textarea v-model="form.description" rows="3" class="form-input"></textarea>
            </div>
            <div class="form-group">
              <label>
                <input v-model="form.enabled" type="checkbox" />
                Enabled
              </label>
            </div>

          </div>
        </div>

        <!-- Tests Tab (show always when creating, or when tab is active when editing) -->
        <div v-if="isCreating || activeTab === 'tests'" class="tab-content" :class="{ 'single-page-section': isCreating }">
          <div class="tests-section">
            <div class="section-header">
              <h2 class="section-title">Assigned Tests</h2>
              <button @click="showAddTestModal = true" class="btn-primary" :disabled="!form.testType">
                <Plus class="btn-icon" />
                Add Test
              </button>
            </div>
            <div v-if="!form.testType" class="info-message">
              <Info class="info-icon" />
              <p>Please select a test type above before adding tests.</p>
            </div>
            <div v-else-if="assignedTests.length === 0" class="empty-state">
              <TestTube class="empty-icon" />
              <h3>No Tests Assigned</h3>
              <p>Add tests to this suite to get started. All tests must be of type: <strong>{{ getTestTypeLabel(form.testType) }}</strong></p>
              <button @click="showAddTestModal = true" class="btn-primary">
                <Plus class="btn-icon" />
                Add Test
              </button>
            </div>
            <div v-else class="tests-list">
              <div
                v-for="test in assignedTests"
                :key="test.id"
                class="test-item"
              >
                <div class="test-info">
                  <div class="test-name-row">
                    <h4 class="test-name">{{ test.name }}</h4>
                    <span class="version-badge">v{{ test.version }}</span>
                  </div>
                  <p v-if="test.description" class="test-description">{{ test.description }}</p>
                  <div v-if="test.testType === 'access-control' && test.policyIds && test.policyIds.length > 0" class="test-policies">
                    <span class="policies-label">Policies:</span>
                    <span
                      v-for="policyId in test.policyIds"
                      :key="policyId"
                      class="policy-badge"
                      @click.stop="viewPolicy(policyId)"
                    >
                      {{ getPolicyName(policyId) }}
                    </span>
                  </div>
                </div>
                <div class="test-actions">
                  <button @click.stop="viewTest(test.id)" class="action-btn">
                    <Eye class="action-icon" />
                    View
                  </button>
                  <button @click.stop="removeTest(test.id)" class="action-btn delete-btn">
                    <X class="action-icon" />
                    Remove
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Add Test Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showAddTestModal" class="modal-overlay" @click="showAddTestModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>Add Tests to Suite</h2>
              <button @click="showAddTestModal = false" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="!form.testType" class="info-message">
                <Info class="info-icon" />
                <p>Please select a test type in the Configuration tab first.</p>
              </div>
              <div v-else>
                <p class="modal-help">Select tests of type: <strong>{{ getTestTypeLabel(form.testType) }}</strong></p>
                <div v-if="loadingTests" class="loading">Loading available tests...</div>
                <div v-else-if="availableTests.length === 0" class="empty-state">
                  <p>No available tests found. <router-link to="/tests/individual">Create a test first</router-link></p>
                </div>
                <div v-else class="tests-selector">
                  <div
                    v-for="test in availableTests"
                    :key="test.id"
                    class="test-option"
                    :class="{ selected: form.testIds.includes(test.id) }"
                    @click="toggleTest(test.id)"
                  >
                    <input
                      type="checkbox"
                      :checked="form.testIds.includes(test.id)"
                      @change="toggleTest(test.id)"
                    />
                    <div class="test-option-info">
                      <div class="test-option-name-row">
                        <span class="test-option-name">{{ test.name }}</span>
                        <span class="version-badge-small">v{{ test.version }}</span>
                      </div>
                      <p v-if="test.description" class="test-option-description">{{ test.description }}</p>
                    </div>
                  </div>
                </div>
                <div class="modal-actions">
                  <button @click="showAddTestModal = false" class="btn-secondary">Cancel</button>
                  <button @click="handleTestsAdded" class="btn-primary">Add Selected Tests</button>
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
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Teleport } from 'vue';
import {
  TestTube,
  Save,
  Play,
  ArrowLeft,
  Info,
  BarChart3,
  Plus,
  X,
  Trash2,
  FileText,
  Eye,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import CrossLinkPanel from '../components/CrossLinkPanel.vue';

const route = useRoute();
const router = useRouter();
const suiteId = computed(() => {
  if (route.name === 'TestSuiteCreate') {
    return 'new';
  }
  return route.params.id as string;
});
const isCreating = computed(() => suiteId.value === 'new');

const loading = ref(true);
const error = ref<string | null>(null);
const saving = ref(false);
const suite = ref<any>(null);
const activeTab = ref('overview');
const showAddTestModal = ref(false);
const assignedTests = ref<any[]>([]);
const availableTests = ref<any[]>([]);
const policies = ref<any[]>([]);
const loadingTests = ref(false);

// Set default tab to overview when editing (tabs only shown when editing)
watch(isCreating, (creating) => {
  if (!creating) {
    activeTab.value = 'overview';
  }
}, { immediate: true });

const tabs = ref([
  { id: 'overview', label: 'Overview', icon: Info },
  { id: 'configuration', label: 'Configuration', icon: FileText },
  { id: 'tests', label: 'Tests', icon: TestTube },
]);

const form = ref({
  name: '',
  application: '',
  team: '',
  testType: '' as string,
  testIds: [] as string[],
  description: '',
  enabled: true,
});

// Filter tabs - only show overview, configuration, and tests
const visibleTabs = computed(() => {
  return tabs.value.filter(t => ['overview', 'configuration', 'tests'].includes(t.id));
});

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
  };
  return labels[testType] || testType;
};


const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: isCreating.value ? 'Create Test Suite' : (suite.value?.name || 'Test Suite') },
]);

const loadSuite = async () => {
  // Skip loading if creating new suite
  if (isCreating.value) {
    loading.value = false;
    error.value = null;
    form.value = {
      name: '',
      application: '',
      team: '',
      testType: '',
      testIds: [],
      description: '',
      enabled: true,
    };
    suite.value = null;
    assignedTests.value = [];
    return;
  }

  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/v1/test-suites/${suiteId.value}`);
    const suiteData = response.data;

    suite.value = suiteData;

    // Populate form
    form.value = {
      name: suiteData.name || '',
      application: suiteData.application || suiteData.applicationId || '',
      team: suiteData.team || '',
      testType: suiteData.testType || '',
      testIds: suiteData.testIds || [],
      description: suiteData.description || '',
      enabled: suiteData.enabled !== false,
    };

    // Load assigned tests
    await loadAssignedTests();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test suite';
    console.error('Error loading test suite:', err);
  } finally {
    loading.value = false;
  }
};

const loadAssignedTests = async () => {
  if (!form.value.testIds || form.value.testIds.length === 0) {
    assignedTests.value = [];
    return;
  }

  loadingTests.value = true;
  try {
    const testPromises = form.value.testIds.map(id => 
      axios.get(`/api/tests/${id}`).catch(() => null)
    );
    const responses = await Promise.all(testPromises);
    assignedTests.value = responses
      .filter(r => r !== null)
      .map(r => r.data)
      .filter(t => t.testType === form.value.testType); // Filter by suite type
  } catch (err) {
    console.error('Error loading assigned tests:', err);
    assignedTests.value = [];
  } finally {
    loadingTests.value = false;
  }
};

const loadAvailableTests = async () => {
  if (!form.value.testType) {
    availableTests.value = [];
    return;
  }

  try {
    const response = await axios.get(`/api/v1/tests?testType=${form.value.testType}`);
    availableTests.value = response.data.filter((test: any) => 
      !form.value.testIds.includes(test.id)
    );
  } catch (err) {
    console.error('Error loading available tests:', err);
    availableTests.value = [];
  }
};

const loadPolicies = async () => {
  try {
    const response = await axios.get('/api/policies');
    policies.value = response.data;
  } catch (err) {
    console.error('Error loading policies:', err);
  }
};

const loadSourceContent = async () => {
  if (suite.value?.sourceType !== 'typescript') return;
  
  sourceLoading.value = true;
  sourceError.value = null;
  try {
    const response = await axios.get(`/api/v1/test-suites/${suiteId.value}/source`);
    sourceContent.value = response.data.content;
    originalSourceContent.value = response.data.content;
  } catch (err: any) {
    sourceError.value = err.response?.data?.message || 'Failed to load source file';
    console.error('Error loading source:', err);
  } finally {
    sourceLoading.value = false;
  }
};

const reloadSource = async () => {
  if (hasSourceChanges.value && !confirm('You have unsaved changes. Reloading will discard them. Continue?')) {
    return;
  }
  await loadSourceContent();
};

const formatSourceCode = () => {
  try {
    // Simple formatter - just try to indent
    let formatted = sourceContent.value;
    let indent = 0;
    const lines = formatted.split('\n');
    formatted = lines.map(line => {
      const trimmed = line.trim();
      if (trimmed.endsWith('{') || trimmed.endsWith('[')) {
        const result = '  '.repeat(indent) + trimmed;
        indent++;
        return result;
      } else if (trimmed.startsWith('}') || trimmed.startsWith(']')) {
        indent = Math.max(0, indent - 1);
        return '  '.repeat(indent) + trimmed;
      } else {
        return '  '.repeat(indent) + trimmed;
      }
    }).join('\n');
    sourceContent.value = formatted;
  } catch (err) {
    console.error('Error formatting code:', err);
    alert('Could not format code. Please check syntax.');
  }
};

const onSourceChange = () => {
  // Content changed, hasSourceChanges computed will update
};

const saveSource = async () => {
  if (!hasSourceChanges.value) return;

  sourceLoading.value = true;
  sourceError.value = null;
  try {
    await axios.put(`/api/v1/test-suites/${suiteId.value}/source`, {
      content: sourceContent.value,
    });
    originalSourceContent.value = sourceContent.value;
    await loadSuite(); // Reload suite to get updated metadata
    alert('Source file saved successfully!');
  } catch (err: any) {
    sourceError.value = err.response?.data?.message || 'Failed to save source file';
    console.error('Error saving source:', err);
    alert(sourceError.value);
  } finally {
    sourceLoading.value = false;
  }
};

const saveSuite = async () => {
  if (!form.value.name || !form.value.application || !form.value.team || !form.value.testType) {
    alert('Please fill in all required fields (name, application, team, test type)');
    return;
  }

  saving.value = true;
  try {
    const payload = {
      name: form.value.name,
      application: form.value.application,
      team: form.value.team,
      testType: form.value.testType,
      testIds: form.value.testIds,
      description: form.value.description,
      enabled: form.value.enabled,
    };

    // If creating new suite
    if (isCreating.value) {
      const response = await axios.post('/api/v1/test-suites', payload);
      const newSuiteId = response.data.id || response.data._id;
      await router.push({ name: 'TestSuiteDetail', params: { id: newSuiteId } });
      return;
    }

    // Update existing suite
    await axios.put(`/api/v1/test-suites/${suiteId.value}`, payload);
    await loadSuite();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to save test suite';
    console.error('Error saving test suite:', err);
    alert(error.value);
  } finally {
    saving.value = false;
  }
};

const convertJSONToTypeScript = (json: any, sourcePath: string, originalContent?: string): string => {
  const suiteName = json.name
    .replace(/[^a-zA-Z0-9]/g, '')
    .replace(/^[a-z]/, (c: string) => c.toUpperCase())
    .replace(/-([a-z])/g, (_, c: string) => c.toUpperCase()) + 'TestSuite';

  let varName = suiteName;
  if (originalContent) {
    const constMatch = originalContent.match(/export\s+const\s+(\w+)\s*:\s*TestSuite/);
    if (constMatch) {
      varName = constMatch[1];
    }
  }

    const config: any = {
      name: json.name,
      application: json.application || json.applicationId,
      team: json.team,
      testType: json.testType || 'access-control',
      userRoles: json.userRoles || [],
      resources: json.resources || [],
      contexts: json.contexts || [],
    };

  if (json.expectedDecisions) config.expectedDecisions = json.expectedDecisions;
  if (json.testQueries) config.testQueries = json.testQueries;
  if (json.allowedFields) config.allowedFields = json.allowedFields;
  if (json.requiredFilters) config.requiredFilters = json.requiredFilters;
  if (json.disallowedJoins) config.disallowedJoins = json.disallowedJoins;
  if (json.datasets) config.datasets = json.datasets;
  if (json.privacyThresholds) config.privacyThresholds = json.privacyThresholds;
  if (json.statisticalFidelityTargets) config.statisticalFidelityTargets = json.statisticalFidelityTargets;

  const configStr = JSON.stringify(config, null, 2);
  
  return `/**
 * ${json.name}
 * ${json.description || `Test suite for ${json.application || json.applicationId}`}
 */

import { TestSuite } from '../core/types';

export const ${varName}: TestSuite = ${configStr};
`;
};

const getTestTypes = (suiteData: any): string[] => {
  // Return array with single test type for backward compatibility
  if (suiteData.testType) {
    const typeMap: Record<string, string> = {
      'access-control': 'Access Control',
      'network-policy': 'Network Policy',
      'dlp': 'Data Loss Prevention (DLP)',
      'distributed-systems': 'Distributed Systems',
      'api-security': 'API Security',
      'data-pipeline': 'Data Pipeline',
    };
    return [typeMap[suiteData.testType] || suiteData.testType];
  }
  // Backward compatibility: infer from old boolean flags
  const types: string[] = [];
  if (suiteData.includeAccessControlTests) types.push('Access Control');
  if (suiteData.includeDatasetHealthTests) types.push('Dataset Health');
  return types;
};

const runSuite = () => {
  // TODO: Implement test suite execution
  alert('Test suite execution not yet implemented');
};

const goBack = () => {
  router.push('/tests');
};

const handleSourceSaved = async () => {
  await loadSuite();
  await loadSourceContent();
};

// Form helpers
const addRole = () => {
  if (newRole.value.trim() && !form.value.userRoles.includes(newRole.value.trim())) {
    form.value.userRoles.push(newRole.value.trim());
    newRole.value = '';
  }
};

const removeRole = (index: number) => {
  const role = form.value.userRoles[index];
  form.value.userRoles.splice(index, 1);
  delete allowedFieldsInput.value[role];
  delete requiredFiltersInput.value[role];
  delete form.value.allowedFields[role];
  delete form.value.requiredFilters[role];
};

const addResource = () => {
  form.value.resources.push({
    id: '',
    type: '',
    sensitivity: '',
  });
};

const removeResource = (index: number) => {
  form.value.resources.splice(index, 1);
};

const addContext = () => {
  form.value.contexts.push({
    ipAddress: '',
    timeOfDay: '',
    location: '',
  });
};

const removeContext = (index: number) => {
  form.value.contexts.splice(index, 1);
};

const addQuery = () => {
  form.value.testQueries.push({
    name: '',
    sql: '',
    apiEndpoint: '',
    httpMethod: '',
  });
};

const removeQuery = (index: number) => {
  form.value.testQueries.splice(index, 1);
};

const addFilter = (role: string) => {
  if (!requiredFiltersInput.value[role]) {
    requiredFiltersInput.value[role] = [];
  }
  requiredFiltersInput.value[role].push({
    field: '',
    operator: '=',
    value: '',
  });
};

const removeFilter = (role: string, index: number) => {
  requiredFiltersInput.value[role].splice(index, 1);
};


const addDataset = () => {
  form.value.datasets.push({
    name: '',
    type: 'raw',
  });
};

const removeDataset = (index: number) => {
  form.value.datasets.splice(index, 1);
};

const formatDate = (date: Date | string | undefined): string => {
  if (!date) return 'Never';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-excellent';
  if (score >= 70) return 'score-good';
  if (score >= 50) return 'score-fair';
  return 'score-poor';
};

// Watch for testType changes to load available tests
watch(() => form.value.testType, (newType) => {
  if (newType) {
    loadAvailableTests();
  }
});

// Watch for showAddTestModal to load available tests when opened
watch(showAddTestModal, (show) => {
  if (show && form.value.testType) {
    loadAvailableTests();
  }
});

onMounted(async () => {
  await Promise.all([loadSuite(), loadPolicies()]);
});

watch([() => route.params.id, () => route.name], () => {
  loadSuite();
});
</script>

<style scoped>
.test-suite-detail-page {
  width: 100%;
  max-width: 1800px;
  margin: 0 auto;
  padding: 24px;
}

.loading,
.error {
  text-align: center;
  padding: 40px;
  color: var(--color-text-secondary);
}

.error {
  color: var(--color-error);
}

.detail-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  margin-top: 16px;
}

.header-left {
  flex: 1;
}

.suite-title-row {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 8px;
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin: 0;
}

.suite-badges {
  display: flex;
  gap: 8px;
  align-items: center;
}

.source-type-badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.source-type-badge.typescript {
  background: rgba(49, 120, 198, 0.2);
  color: #3178c6;
  border: 1px solid rgba(49, 120, 198, 0.3);
}

.source-type-badge.json {
  background: rgba(255, 193, 7, 0.2);
  color: #ffc107;
  border: 1px solid rgba(255, 193, 7, 0.3);
}

.suite-status {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-passing {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failing {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.status-pending {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.enabled-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.enabled-badge.enabled {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
}

.enabled-badge.disabled {
  background: var(--color-gray-400-alpha-20);
  color: var(--color-text-secondary);
}

.suite-meta {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: var(--spacing-sm) 0;
}

.source-path {
  font-size: 0.875rem;
  color: #718096;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
}

.suite-description {
  font-size: 1rem;
  color: #cbd5e0;
  margin-top: 12px;
}

.header-actions {
  display: flex;
  gap: 12px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.action-btn.save-btn {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.action-btn.run-btn {
  background: var(--color-success-bg);
  color: var(--color-success);
  border: var(--border-width-thin) solid var(--border-success);
}

.action-btn.cancel-btn {
  background: var(--color-gray-400-alpha-10);
  color: var(--color-text-secondary);
  border: var(--border-width-thin) solid var(--border-color-muted);
}

.action-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.action-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.tabs-container {
  margin-bottom: 24px;
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tabs {
  display: flex;
  gap: var(--spacing-xs);
  overflow-x: auto;
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) 20px;
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  white-space: nowrap;
}

.tab-button:hover {
  color: var(--color-primary);
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
  background: rgba(79, 172, 254, 0.1);
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.tab-content-container {
  min-height: 400px;
}

.tab-content-container.creation-layout {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 2rem;
}

@media (max-width: 1400px) {
  .tab-content-container.creation-layout {
    grid-template-columns: 1fr;
  }
}

.tab-content {
  animation: fadeIn 0.3s;
}

.single-page-section {
  margin-bottom: 0;
}

/* Tests Section Styling - matches form-section */
.tests-section {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-lg);
}

.tests-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-top: 24px;
}

.test-item {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 20px;
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  transition: all 0.2s;
}

.test-item:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(26, 31, 46, 0.7);
}

.test-info {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.test-name-row {
  display: flex;
  align-items: center;
  gap: 12px;
}

.test-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.version-badge {
  display: inline-flex;
  align-items: center;
  padding: var(--spacing-xs) 10px;
  background: var(--color-info-bg);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.test-description {
  font-size: 0.875rem;
  color: #cbd5e0;
  margin: 0;
  line-height: 1.5;
}

.test-policies {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.policies-label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.policy-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  background: rgba(16, 185, 129, 0.2);
  color: #10b981;
  border: 1px solid rgba(16, 185, 129, 0.3);
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.policy-badge:hover {
  background: rgba(16, 185, 129, 0.3);
  border-color: rgba(16, 185, 129, 0.5);
}

.test-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-left: 16px;
}

.test-actions .action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.test-actions .action-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.test-actions .action-btn.delete-btn {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.test-actions .action-btn.delete-btn:hover {
  background: rgba(239, 68, 68, 0.2);
  border-color: rgba(239, 68, 68, 0.4);
}

.test-actions .action-icon {
  width: 16px;
  height: 16px;
}

.info-message {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  margin-top: 24px;
}

.info-message .info-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 2px;
}

.info-message p {
  margin: 0;
  font-size: 0.875rem;
  color: #cbd5e0;
  line-height: 1.5;
}

.empty-state {
  text-align: center;
  padding: 48px 24px;
  margin-top: 24px;
  color: #a0aec0;
}

.empty-state .empty-icon {
  width: 64px;
  height: 64px;
  color: rgba(79, 172, 254, 0.4);
  margin: 0 auto 16px;
}

.empty-state h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.empty-state p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 24px 0;
  line-height: 1.5;
}

.empty-state .btn-primary {
  margin: 0 auto;
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(10px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
}

.info-card,
.stats-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 20px 0;
}

.title-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.info-list,
.stats-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.info-item,
.stat-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.info-item:last-child,
.stat-item:last-child {
  border-bottom: none;
}

.info-label,
.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.info-value,
.stat-value {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 500;
}

.source-path-value {
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 0.75rem;
  color: #718096;
}

.test-types-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 16px;
}

.test-type-badge {
  display: inline-block;
  padding: 4px 12px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.score {
  font-weight: 600;
}

.score-excellent {
  color: #22c55e;
}

.score-good {
  color: #4facfe;
}

.score-fair {
  color: #fbbf24;
}

.score-poor {
  color: #ef4444;
}

.form-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-header .btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.section-header .btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.section-header .btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.section-header .btn-primary .btn-icon {
  width: 16px;
  height: 16px;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 20px;
  margin-bottom: 24px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group.full-width {
  grid-column: 1 / -1;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #cbd5e0;
}

.form-input {
  padding: 10px 12px;
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234facfe' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  padding-right: 40px;
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
  color: #cbd5e0;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px;
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 50px;
}

.tag {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 16px;
  font-size: 0.875rem;
}

.tag-remove {
  background: none;
  border: none;
  color: #4facfe;
  cursor: pointer;
  padding: 0;
  display: flex;
  align-items: center;
}

.tag-icon {
  width: 14px;
  height: 14px;
}

.tag-input {
  flex: 1;
  min-width: 200px;
  background: transparent;
  border: none;
  color: #ffffff;
  font-size: 0.875rem;
  outline: none;
}

.btn-small {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: rgba(79, 172, 254, 0.2);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.3);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.resources-list,
.contexts-list,
.queries-list,
.contracts-list,
.datasets-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.resource-card,
.context-card,
.query-card,
.contract-card,
.dataset-card {
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
}

.resource-header,
.context-header,
.query-header,
.contract-header,
.dataset-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.resource-header h4,
.context-header h4,
.query-header h4,
.contract-header h4,
.dataset-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-icon-only {
  background: transparent;
  border: 1px solid rgba(239, 68, 68, 0.3);
  border-radius: 6px;
  padding: 6px;
  color: #ef4444;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-icon-only:hover {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.5);
}

.btn-icon-only .icon {
  width: 16px;
  height: 16px;
}

/* Empty state styling is defined below in tests section */

.empty-state-info {
  margin-top: 24px;
  padding: 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  text-align: left;
  max-width: 600px;
  margin-left: auto;
  margin-right: auto;
}

.empty-state-info ol {
  margin: 12px 0 0 0;
  padding-left: 24px;
}

.empty-state-info li {
  margin-bottom: 8px;
  color: #cbd5e0;
}

.empty-state-help {
  margin-top: 12px;
  font-size: 0.875rem;
  color: #718096;
  font-style: italic;
}

.creation-guide {
  margin-bottom: 24px;
  padding: 20px;
  background: linear-gradient(135deg, rgba(79, 172, 254, 0.1) 0%, rgba(0, 242, 254, 0.05) 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
}

.guide-content {
  display: flex;
  gap: 16px;
  align-items: flex-start;
}

.guide-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 4px;
}

.guide-text {
  flex: 1;
}

.guide-text h3 {
  margin: 0 0 8px 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.guide-text > p {
  margin: 0 0 16px 0;
  color: #cbd5e0;
  font-size: 0.9rem;
}

.guide-steps {
  margin: 0;
  padding-left: 24px;
  color: #cbd5e0;
}

.guide-steps li {
  margin-bottom: 8px;
  line-height: 1.6;
}

.test-type-info {
  margin-top: 12px;
  padding: 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.test-type-info p {
  margin: 0 0 8px 0;
  color: #cbd5e0;
  font-size: 0.875rem;
}

.test-type-info p:last-child {
  margin-bottom: 0;
}

.test-generation-note {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 8px !important;
  padding-top: 8px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  font-size: 0.8rem !important;
  color: #a0aec0 !important;
}

.info-icon-small {
  width: 16px;
  height: 16px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 2px;
}

.filters-section {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.role-fields-card,
.role-filters-card {
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 20px;
}

.role-fields-card h4,
.role-filters-card h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.role-filters-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.filter-item {
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.filter-item:last-child {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.source-editor-embedded {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.loading-state,
.error-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.error-state {
  color: #f87171;
}

.editor-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.editor-toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: rgba(26, 31, 46, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.file-type-badge {
  display: inline-block;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.file-type-badge.typescript {
  background: rgba(49, 120, 198, 0.2);
  color: #3178c6;
  border: 1px solid rgba(49, 120, 198, 0.3);
}

.toolbar-actions {
  display: flex;
  gap: 8px;
}

.toolbar-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.toolbar-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.toolbar-btn .icon {
  width: 14px;
  height: 14px;
}

.source-editor {
  width: 100%;
  min-height: 500px;
  padding: 16px;
  background: #1a1f2e;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #e2e8f0;
  font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
  font-size: 14px;
  line-height: 1.6;
  resize: vertical;
  outline: none;
  tab-size: 2;
}

.source-editor:focus {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.unsaved-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 6px;
  color: #fbbf24;
  font-size: 0.875rem;
}

.unsaved-indicator .icon {
  width: 16px;
  height: 16px;
}

.source-editor-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 16px;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-primary .icon {
  width: 16px;
  height: 16px;
}
</style>

