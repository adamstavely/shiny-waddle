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

      <!-- Tabs -->
      <div class="tabs-container">
        <div class="tabs">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            v-show="!isCreating || tab.id !== 'source'"
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
      <div class="tab-content-container">
        <!-- Overview Tab -->
        <div v-if="activeTab === 'overview'" class="tab-content">
          <div v-if="isCreating" class="empty-state">
            <Info class="empty-icon" />
            <h3>Create a New Test Suite</h3>
            <p>Use the Configuration tab to set up your test suite details.</p>
          </div>
          <div v-else class="overview-grid">
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
        </div>

        <!-- Configuration Tab -->
        <div v-if="activeTab === 'configuration'" class="tab-content">
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
              <h2 class="section-title">Test Types</h2>
            </div>
            <div class="checkbox-group">
              <label class="checkbox-label">
                <input v-model="form.includeAccessControlTests" type="checkbox" />
                Access Control Tests
              </label>
              <label class="checkbox-label">
                <input v-model="form.includeDataBehaviorTests" type="checkbox" />
                Data Behavior Tests
              </label>
              <label class="checkbox-label">
                <input v-model="form.includeContractTests" type="checkbox" />
                Contract Tests
              </label>
              <label class="checkbox-label">
                <input v-model="form.includeDatasetHealthTests" type="checkbox" />
                Dataset Health Tests
              </label>
            </div>

            <div class="section-header">
              <h2 class="section-title">User Roles</h2>
              <button @click="addRole" class="btn-small">
                <Plus class="btn-icon-small" />
                Add Role
              </button>
            </div>
            <div class="tags-input">
              <span
                v-for="(role, index) in form.userRoles"
                :key="index"
                class="tag"
              >
                {{ role }}
                <button type="button" @click="removeRole(index)" class="tag-remove">
                  <X class="tag-icon" />
                </button>
              </span>
              <input
                v-model="newRole"
                type="text"
                placeholder="Add role and press Enter"
                @keydown.enter.prevent="addRole"
                class="tag-input"
              />
            </div>
          </div>
        </div>

        <!-- Resources Tab -->
        <div v-if="activeTab === 'resources'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Resources</h2>
            <button @click="addResource" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Resource
            </button>
          </div>
          <div class="resources-list">
            <div v-for="(resource, index) in form.resources" :key="index" class="resource-card">
              <div class="resource-header">
                <h4>Resource {{ index + 1 }}</h4>
                <button @click="removeResource(index)" class="btn-icon-only">
                  <Trash2 class="icon" />
                </button>
              </div>
              <div class="form-grid">
                <div class="form-group">
                  <label>Resource ID</label>
                  <input v-model="resource.id" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Type</label>
                  <input v-model="resource.type" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Sensitivity</label>
                  <select v-model="resource.sensitivity" class="form-input">
                    <option value="">None</option>
                    <option value="public">Public</option>
                    <option value="internal">Internal</option>
                    <option value="confidential">Confidential</option>
                    <option value="restricted">Restricted</option>
                  </select>
                </div>
              </div>
            </div>
            <div v-if="form.resources.length === 0" class="empty-state">
              <p>No resources configured. Click "Add Resource" to get started.</p>
            </div>
          </div>
        </div>

        <!-- Contexts Tab -->
        <div v-if="activeTab === 'contexts'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Contexts</h2>
            <button @click="addContext" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Context
            </button>
          </div>
          <div class="contexts-list">
            <div v-for="(context, index) in form.contexts" :key="index" class="context-card">
              <div class="context-header">
                <h4>Context {{ index + 1 }}</h4>
                <button @click="removeContext(index)" class="btn-icon-only">
                  <Trash2 class="icon" />
                </button>
              </div>
              <div class="form-grid">
                <div class="form-group">
                  <label>IP Address</label>
                  <input v-model="context.ipAddress" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Time of Day</label>
                  <input v-model="context.timeOfDay" type="text" placeholder="HH:MM" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Location</label>
                  <input v-model="context.location" type="text" class="form-input" />
                </div>
              </div>
            </div>
            <div v-if="form.contexts.length === 0" class="empty-state">
              <p>No contexts configured. Click "Add Context" to get started.</p>
            </div>
          </div>
        </div>

        <!-- Test Queries Tab -->
        <div v-if="activeTab === 'queries'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Test Queries</h2>
            <button @click="addQuery" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Query
            </button>
          </div>
          <div class="queries-list">
            <div v-for="(query, index) in form.testQueries" :key="index" class="query-card">
              <div class="query-header">
                <h4>Query {{ index + 1 }}</h4>
                <button @click="removeQuery(index)" class="btn-icon-only">
                  <Trash2 class="icon" />
                </button>
              </div>
              <div class="form-grid">
                <div class="form-group">
                  <label>Query Name</label>
                  <input v-model="query.name" type="text" class="form-input" />
                </div>
                <div class="form-group full-width">
                  <label>SQL</label>
                  <textarea v-model="query.sql" class="form-input" rows="3"></textarea>
                </div>
                <div class="form-group">
                  <label>API Endpoint</label>
                  <input v-model="query.apiEndpoint" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>HTTP Method</label>
                  <input v-model="query.httpMethod" type="text" class="form-input" />
                </div>
              </div>
            </div>
            <div v-if="form.testQueries.length === 0" class="empty-state">
              <p>No test queries configured. Click "Add Query" to get started.</p>
            </div>
          </div>
        </div>

        <!-- Data Behavior Tab -->
        <div v-if="activeTab === 'data-behavior'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Allowed Fields</h2>
          </div>
          <div class="data-behavior-section">
            <div v-for="role in form.userRoles" :key="role" class="role-fields-card">
              <h4>{{ role }}</h4>
              <div class="form-group">
                <label>Allowed Fields (comma-separated)</label>
                <input
                  v-model="allowedFieldsInput[role]"
                  type="text"
                  class="form-input"
                  :placeholder="`e.g., id, name, email`"
                />
              </div>
            </div>
          </div>

          <div class="section-header">
            <h2 class="section-title">Required Filters</h2>
          </div>
          <div class="filters-section">
            <div v-for="role in form.userRoles" :key="role" class="role-filters-card">
              <div class="role-filters-header">
                <h4>{{ role }}</h4>
                <button @click="addFilter(role)" class="btn-small">
                  <Plus class="btn-icon-small" />
                  Add Filter
                </button>
              </div>
              <div v-for="(filter, index) in (requiredFiltersInput[role] || [])" :key="index" class="filter-item">
                <div class="form-grid">
                  <div class="form-group">
                    <label>Field</label>
                    <input v-model="filter.field" type="text" class="form-input" />
                  </div>
                  <div class="form-group">
                    <label>Operator</label>
                    <select v-model="filter.operator" class="form-input">
                      <option value="=">=</option>
                      <option value="!=">!=</option>
                      <option value=">">&gt;</option>
                      <option value="<">&lt;</option>
                      <option value=">=">&gt;=</option>
                      <option value="<=">&lt;=</option>
                      <option value="IN">IN</option>
                      <option value="NOT IN">NOT IN</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Value</label>
                    <input v-model="filter.value" type="text" class="form-input" />
                  </div>
                  <div class="form-group">
                    <button @click="removeFilter(role, index)" class="btn-icon-only">
                      <Trash2 class="icon" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Contracts Tab -->
        <div v-if="activeTab === 'contracts'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Contracts</h2>
            <button @click="addContract" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Contract
            </button>
          </div>
          <div class="contracts-list">
            <div v-for="(contract, index) in form.contracts" :key="index" class="contract-card">
              <div class="contract-header">
                <h4>{{ contract.name || `Contract ${index + 1}` }}</h4>
                <button @click="removeContract(index)" class="btn-icon-only">
                  <Trash2 class="icon" />
                </button>
              </div>
              <div class="form-grid">
                <div class="form-group">
                  <label>Contract Name</label>
                  <input v-model="contract.name" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Data Owner</label>
                  <input v-model="contract.dataOwner" type="text" class="form-input" />
                </div>
              </div>
            </div>
            <div v-if="form.contracts.length === 0" class="empty-state">
              <p>No contracts configured. Click "Add Contract" to get started.</p>
            </div>
          </div>
        </div>

        <!-- Datasets Tab -->
        <div v-if="activeTab === 'datasets'" class="tab-content">
          <div class="section-header">
            <h2 class="section-title">Datasets</h2>
            <button @click="addDataset" class="btn-small">
              <Plus class="btn-icon-small" />
              Add Dataset
            </button>
          </div>
          <div class="datasets-list">
            <div v-for="(dataset, index) in form.datasets" :key="index" class="dataset-card">
              <div class="dataset-header">
                <h4>{{ dataset.name || `Dataset ${index + 1}` }}</h4>
                <button @click="removeDataset(index)" class="btn-icon-only">
                  <Trash2 class="icon" />
                </button>
              </div>
              <div class="form-grid">
                <div class="form-group">
                  <label>Dataset Name</label>
                  <input v-model="dataset.name" type="text" class="form-input" />
                </div>
                <div class="form-group">
                  <label>Type</label>
                  <select v-model="dataset.type" class="form-input">
                    <option value="raw">Raw</option>
                    <option value="masked">Masked</option>
                    <option value="synthetic">Synthetic</option>
                  </select>
                </div>
              </div>
            </div>
            <div v-if="form.datasets.length === 0" class="empty-state">
              <p>No datasets configured. Click "Add Dataset" to get started.</p>
            </div>
          </div>
        </div>

        <!-- Source Code Tab (TypeScript only) -->
        <div v-if="activeTab === 'source' && suite.sourceType === 'typescript'" class="tab-content">
          <div class="source-editor-embedded">
            <div v-if="sourceLoading" class="loading-state">
              <p>Loading source file...</p>
            </div>
            
            <div v-else-if="sourceError" class="error-state">
              <p>{{ sourceError }}</p>
            </div>
            
            <div v-else class="editor-container">
              <div class="editor-toolbar">
                <span class="file-type-badge typescript">
                  TypeScript
                </span>
                <div class="toolbar-actions">
                  <button @click="formatSourceCode" class="toolbar-btn" title="Format code">
                    <FileText class="icon" />
                    Format
                  </button>
                  <button @click="reloadSource" class="toolbar-btn" title="Reload from file">
                    <RefreshCw class="icon" />
                    Reload
                  </button>
                </div>
              </div>
              
              <textarea
                v-model="sourceContent"
                class="source-editor typescript"
                spellcheck="false"
                @input="onSourceChange"
              ></textarea>
              
              <div v-if="hasSourceChanges" class="unsaved-indicator">
                <AlertCircle class="icon" />
                <span>Unsaved changes</span>
              </div>
              <div class="source-editor-actions">
                <button @click="saveSource" class="btn-primary" :disabled="sourceLoading || !hasSourceChanges">
                  <Save class="icon" />
                  Save Source
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
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
  User,
  Database,
  Globe,
  Code,
  Shield,
  RefreshCw,
  AlertCircle,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';

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
const newRole = ref('');

// Set default tab to configuration when creating
watch(isCreating, (creating) => {
  if (creating) {
    activeTab.value = 'configuration';
  }
}, { immediate: true });

const tabs = ref([
  { id: 'overview', label: 'Overview', icon: Info },
  { id: 'configuration', label: 'Configuration', icon: FileText },
  { id: 'resources', label: 'Resources', icon: Database },
  { id: 'contexts', label: 'Contexts', icon: Globe },
  { id: 'queries', label: 'Test Queries', icon: Code },
  { id: 'data-behavior', label: 'Data Behavior', icon: Shield },
  { id: 'contracts', label: 'Contracts', icon: FileText },
  { id: 'datasets', label: 'Datasets', icon: BarChart3 },
]);

const form = ref({
  name: '',
  application: '',
  team: '',
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeContractTests: false,
  includeDatasetHealthTests: false,
  userRoles: [] as string[],
  resources: [] as any[],
  contexts: [] as any[],
  testQueries: [] as any[],
  allowedFields: {} as Record<string, string[]>,
  requiredFilters: {} as Record<string, any[]>,
  contracts: [] as any[],
  datasets: [] as any[],
});

const allowedFieldsInput = ref<Record<string, string>>({});
const requiredFiltersInput = ref<Record<string, any[]>>({});

// Source editor state
const sourceLoading = ref(false);
const sourceError = ref<string | null>(null);
const sourceContent = ref('');
const originalSourceContent = ref('');
const hasSourceChanges = computed(() => sourceContent.value !== originalSourceContent.value);

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
    // Initialize form with default values
    form.value = {
      name: '',
      application: '',
      team: '',
      includeAccessControlTests: true,
      includeDataBehaviorTests: true,
      includeContractTests: false,
      includeDatasetHealthTests: false,
      userRoles: [],
      resources: [],
      contexts: [],
      testQueries: [],
      allowedFields: {},
      requiredFilters: {},
      contracts: [],
      datasets: [],
    };
    suite.value = null;
    return;
  }

  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get(`/api/test-suites/${suiteId.value}`);
    let suiteData = response.data;

    // If it's a TypeScript suite, extract the full config
    if (suiteData.sourceType === 'typescript' && suiteData.sourcePath) {
      try {
        const extractResponse = await axios.get(`/api/test-suites/${suiteId.value}/extract-config`);
        const extractedConfig = extractResponse.data.config;
        suiteData = {
          ...suiteData,
          ...extractedConfig,
          application: extractedConfig.application || suiteData.application || suiteData.applicationId,
        };
      } catch (err: any) {
        console.warn('Could not extract full config from TypeScript source:', err);
      }
    }

    suite.value = suiteData;
    
    // Populate form
    form.value = {
      name: suiteData.name || '',
      application: suiteData.application || suiteData.applicationId || '',
      team: suiteData.team || '',
      includeAccessControlTests: suiteData.includeAccessControlTests ?? true,
      includeDataBehaviorTests: suiteData.includeDataBehaviorTests ?? true,
      includeContractTests: suiteData.includeContractTests ?? false,
      includeDatasetHealthTests: suiteData.includeDatasetHealthTests ?? false,
      userRoles: suiteData.userRoles || [],
      resources: suiteData.resources || [],
      contexts: suiteData.contexts || [],
      testQueries: suiteData.testQueries || [],
      allowedFields: suiteData.allowedFields || {},
      requiredFilters: suiteData.requiredFilters || {},
      contracts: suiteData.contracts || [],
      datasets: suiteData.datasets || [],
    };

    // Initialize input fields
    form.value.userRoles.forEach(role => {
      allowedFieldsInput.value[role] = (suiteData.allowedFields?.[role] || []).join(', ');
      requiredFiltersInput.value[role] = suiteData.requiredFilters?.[role] || [];
    });

    // Add source tab if TypeScript
    if (suiteData.sourceType === 'typescript' && !tabs.value.find(t => t.id === 'source')) {
      tabs.value.push({ id: 'source', label: 'Source Code', icon: Code });
    }
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load test suite';
    console.error('Error loading test suite:', err);
  } finally {
    loading.value = false;
  }
};

const loadSourceContent = async () => {
  if (suite.value?.sourceType !== 'typescript') return;
  
  sourceLoading.value = true;
  sourceError.value = null;
  try {
    const response = await axios.get(`/api/test-suites/${suiteId.value}/source`);
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
    await axios.put(`/api/test-suites/${suiteId.value}/source`, {
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
  saving.value = true;
  try {
    // Process allowed fields
    const allowedFields: Record<string, string[]> = {};
    form.value.userRoles.forEach(role => {
      const input = allowedFieldsInput.value[role];
      if (input) {
        allowedFields[role] = input.split(',').map(f => f.trim()).filter(f => f);
      }
    });
    form.value.allowedFields = allowedFields;
    form.value.requiredFilters = requiredFiltersInput.value;

    const suiteData = { ...form.value };
    const testTypes = getTestTypes(suiteData);
    const payload = {
      ...suiteData,
      applicationId: suiteData.applicationId || suiteData.application,
      testTypes,
    };

    // If creating new suite
    if (isCreating.value) {
      const response = await axios.post('/api/test-suites', {
        ...payload,
        status: 'pending',
        testCount: 0,
        score: 0,
      });
      // Navigate to the new suite's detail page
      const newSuiteId = response.data.id || response.data._id;
      await router.push({ name: 'TestSuiteDetail', params: { id: newSuiteId } });
      alert('Test suite created successfully!');
      return;
    }

    // If TypeScript suite, convert to TypeScript and update source
    if (suite.value?.sourceType === 'typescript' && suite.value.sourcePath) {
      try {
        const sourceResponse = await axios.get(`/api/test-suites/${suiteId.value}/source`);
        const originalContent = sourceResponse.data.content;
        
        const tsContent = convertJSONToTypeScript(suiteData, suite.value.sourcePath, originalContent);
        
        await axios.put(`/api/test-suites/${suiteId.value}/source`, {
          content: tsContent,
        });
        
        await loadSuite();
        alert('Test suite saved successfully!');
        return;
      } catch (err: any) {
        console.error('Error updating TypeScript source:', err);
        alert('Failed to update TypeScript source file. Please use the source code editor instead.');
        return;
      }
    }

    // For JSON-based suites, use regular update
    await axios.put(`/api/test-suites/${suiteId.value}`, payload);
    await loadSuite();
    alert('Test suite saved successfully!');
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
    includeAccessControlTests: json.includeAccessControlTests || false,
    includeDataBehaviorTests: json.includeDataBehaviorTests || false,
    includeContractTests: json.includeContractTests || false,
    includeDatasetHealthTests: json.includeDatasetHealthTests || false,
    userRoles: json.userRoles || [],
    resources: json.resources || [],
    contexts: json.contexts || [],
  };

  if (json.expectedDecisions) config.expectedDecisions = json.expectedDecisions;
  if (json.testQueries) config.testQueries = json.testQueries;
  if (json.allowedFields) config.allowedFields = json.allowedFields;
  if (json.requiredFilters) config.requiredFilters = json.requiredFilters;
  if (json.disallowedJoins) config.disallowedJoins = json.disallowedJoins;
  if (json.contracts) config.contracts = json.contracts;
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
  const types: string[] = [];
  if (suiteData.includeAccessControlTests) types.push('Access Control');
  if (suiteData.includeDataBehaviorTests) types.push('Data Behavior');
  if (suiteData.includeContractTests) types.push('Contract');
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

const addContract = () => {
  form.value.contracts.push({
    name: '',
    dataOwner: '',
  });
};

const removeContract = (index: number) => {
  form.value.contracts.splice(index, 1);
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

onMounted(() => {
  loadSuite();
});

watch([() => route.params.id, () => route.name], () => {
  loadSuite();
});

watch(() => activeTab.value, (newTab) => {
  // Load source content when switching to source tab
  if (newTab === 'source' && suite.value?.sourceType === 'typescript' && !sourceContent.value) {
    loadSourceContent();
  }
});
</script>

<style scoped>
.test-suite-detail-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.loading,
.error {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.error {
  color: #f87171;
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
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
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
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.suite-meta {
  font-size: 1rem;
  color: #a0aec0;
  margin: 8px 0;
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
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.action-btn.run-btn {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.action-btn.cancel-btn {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.2);
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
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tabs {
  display: flex;
  gap: 4px;
  overflow-x: auto;
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
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.tab-button:hover {
  color: #4facfe;
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.tab-content-container {
  min-height: 400px;
}

.tab-content {
  animation: fadeIn 0.3s;
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

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.data-behavior-section,
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

