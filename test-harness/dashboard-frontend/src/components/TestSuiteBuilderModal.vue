<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <TestTube class="modal-title-icon" />
              <h2>{{ editingSuite ? 'Edit Test Suite' : 'Create Test Suite' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <div v-if="editingSuite?._isTypeScript" class="typescript-warning">
              <AlertTriangle class="warning-icon" />
              <div class="warning-content">
                <strong>TypeScript Source File</strong>
                <p v-if="editingSuite?._extractionFailed">
                  Warning: Could not fully extract configuration from TypeScript source. 
                  Some fields may be missing. Use the source code editor for complete editing.
                </p>
                <p v-else>
                  This test suite is defined in a TypeScript file. Editing will update the source file directly. 
                  For advanced editing, use the source code editor.
                </p>
              </div>
            </div>
            <div class="builder-tabs">
              <button
                v-for="tab in tabs"
                :key="tab.id"
                @click="activeTab = tab.id"
                class="builder-tab"
                :class="{ active: activeTab === tab.id }"
              >
                <component :is="tab.icon" class="tab-icon" />
                {{ tab.label }}
              </button>
            </div>

            <form @submit.prevent="save" class="suite-form">
              <!-- Basic Information Tab -->
              <div v-if="activeTab === 'basic'" class="tab-panel">
                <div class="form-group">
                  <label>Test Suite Name *</label>
                  <input v-model="form.name" type="text" required />
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Application *</label>
                    <input v-model="form.application" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Team *</label>
                    <input v-model="form.team" type="text" required />
                  </div>
                </div>
                <div class="form-group">
                  <label>Test Type *</label>
                  <select v-model="form.testType" required class="form-select">
                    <option value="">Select a test type...</option>
                    <option value="access-control">Access Control</option>
                    <option value="network-policy">Network Policy</option>
                    <option value="dlp">Data Loss Prevention (DLP)</option>
                    <option value="distributed-systems">Distributed Systems</option>
                    <option value="api-security">API Security</option>
                    <option value="data-pipeline">Data Pipeline</option>
                  </select>
                  <small>Each test suite must have exactly one test type. All tests in this suite will be of the selected type.</small>
                </div>
              </div>

              <!-- Expected Decisions Tab (only for access-control type) -->
              <div v-if="activeTab === 'expected-decisions' && form.testType === 'access-control'" class="tab-panel">
                <div class="section-header">
                  <h3>Expected Decisions</h3>
                  <p class="form-help">Define expected access control decisions for user/resource combinations</p>
                </div>
                <div v-if="form.userRoles.length === 0 || form.resources.length === 0" class="info-message">
                  <p>Please add user roles and resources first to define expected decisions.</p>
                </div>
                <div v-else class="decisions-grid">
                  <div
                    v-for="role in form.userRoles"
                    :key="role"
                    class="role-decisions"
                  >
                    <h4>{{ role }}</h4>
                    <div
                      v-for="resource in form.resources"
                      :key="resource.id"
                      class="decision-item"
                    >
                      <label class="decision-label">
                        <span class="resource-name">{{ resource.id }} ({{ resource.type }})</span>
                        <select
                          v-model="form.expectedDecisions[`${role}-${resource.type}`]"
                          class="decision-select"
                        >
                          <option :value="undefined">Not Set</option>
                          <option :value="true">Allow</option>
                          <option :value="false">Deny</option>
                        </select>
                      </label>
                    </div>
                  </div>
                </div>
              </div>

              <!-- User Roles Tab -->
              <div v-if="activeTab === 'users'" class="tab-panel">
                <div class="form-group">
                  <label>User Roles</label>
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
                  <small>Press Enter to add a role</small>
                </div>
              </div>

              <!-- Resources Tab -->
              <div v-if="activeTab === 'resources'" class="tab-panel">
                <div class="section-header">
                  <h3>Resources</h3>
                  <button type="button" @click="addResource" class="btn-small">
                    <Plus class="btn-icon-small" />
                    Add Resource
                  </button>
                </div>
                <div v-for="(resource, index) in form.resources" :key="index" class="resource-item">
                  <div class="form-row">
                    <div class="form-group">
                      <label>Resource ID</label>
                      <input v-model="resource.id" type="text" />
                    </div>
                    <div class="form-group">
                      <label>Type</label>
                      <input v-model="resource.type" type="text" />
                    </div>
                    <div class="form-group">
                      <label>Sensitivity</label>
                      <select v-model="resource.sensitivity">
                        <option value="">None</option>
                        <option value="public">Public</option>
                        <option value="internal">Internal</option>
                        <option value="confidential">Confidential</option>
                        <option value="restricted">Restricted</option>
                      </select>
                    </div>
                    <button type="button" @click="removeResource(index)" class="btn-icon-only">
                      <X class="icon" />
                    </button>
                  </div>
                </div>
              </div>

              <!-- Contexts Tab -->
              <div v-if="activeTab === 'contexts'" class="tab-panel">
                <div class="section-header">
                  <h3>Contexts</h3>
                  <button type="button" @click="addContext" class="btn-small">
                    <Plus class="btn-icon-small" />
                    Add Context
                  </button>
                </div>
                <div v-for="(context, index) in form.contexts" :key="index" class="context-item">
                  <div class="form-row">
                    <div class="form-group">
                      <label>IP Address</label>
                      <input v-model="context.ipAddress" type="text" />
                    </div>
                    <div class="form-group">
                      <label>Time of Day</label>
                      <input v-model="context.timeOfDay" type="text" placeholder="HH:MM" />
                    </div>
                    <div class="form-group">
                      <label>Location</label>
                      <input v-model="context.location" type="text" />
                    </div>
                    <button type="button" @click="removeContext(index)" class="btn-icon-only">
                      <X class="icon" />
                    </button>
                  </div>
                </div>
              </div>

              <!-- Datasets Tab (only for dataset-health type) -->
              <div v-if="activeTab === 'datasets' && form.testType === 'dataset-health'" class="tab-panel">
                <div class="section-header">
                  <h3>Datasets</h3>
                  <button type="button" @click="addDataset" class="btn-small">
                    <Plus class="btn-icon-small" />
                    Add Dataset
                  </button>
                </div>
                <div v-for="(dataset, index) in form.datasets" :key="index" class="dataset-item">
                  <div class="form-row">
                    <div class="form-group">
                      <label>Dataset Name</label>
                      <input v-model="dataset.name" type="text" />
                    </div>
                    <div class="form-group">
                      <label>Type</label>
                      <select v-model="dataset.type">
                        <option value="raw">Raw</option>
                        <option value="masked">Masked</option>
                        <option value="synthetic">Synthetic</option>
                      </select>
                    </div>
                    <button type="button" @click="removeDataset(index)" class="btn-icon-only">
                      <X class="icon" />
                    </button>
                  </div>
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="button" @click="saveAsDraft" class="btn-secondary">
                  Save as Draft
                </button>
                <button type="submit" class="btn-primary">Save Test Suite</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue';
import { Teleport } from 'vue';
import {
  TestTube,
  X,
  Plus,
  User,
  Database,
  Globe,
  Code,
  Shield,
  FileText,
  BarChart3,
  AlertTriangle
} from 'lucide-vue-next';

interface Resource {
  id: string;
  type: string;
  attributes?: Record<string, any>;
  sensitivity?: string;
}

interface Context {
  ipAddress?: string;
  timeOfDay?: string;
  location?: string;
  device?: string;
  additionalAttributes?: Record<string, any>;
}

interface TestQuery {
  name: string;
  sql?: string;
  apiEndpoint?: string;
  httpMethod?: string;
  requestBody?: any;
}

interface Contract {
  name: string;
  dataOwner: string;
  requirements?: any[];
  machineReadable?: boolean;
}

interface Dataset {
  name: string;
  type: 'raw' | 'masked' | 'synthetic';
  schema?: any;
  recordCount?: number;
  piiFields?: string[];
}

interface Filter {
  field: string;
  operator: string;
  value: any;
}

interface Props {
  show: boolean;
  editingSuite?: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [data: any];
  saveDraft: [data: any];
}>();

const activeTab = ref('basic');
const newRole = ref('');

const tabs = [
  { id: 'basic', label: 'Basic Info', icon: FileText },
  { id: 'users', label: 'User Roles', icon: User },
  { id: 'resources', label: 'Resources', icon: Database },
  { id: 'contexts', label: 'Contexts', icon: Globe },
  { id: 'expected-decisions', label: 'Expected Decisions', icon: Shield },
  { id: 'datasets', label: 'Datasets', icon: BarChart3 }
];

const form = ref({
  name: '',
  application: '',
  team: '',
  testType: '' as string,
  userRoles: [] as string[],
  resources: [] as Resource[],
  contexts: [] as Context[],
  expectedDecisions: {} as Record<string, boolean>,
  testQueries: [] as TestQuery[],
  allowedFields: {} as Record<string, string[]>,
  requiredFilters: {} as Record<string, Filter[]>,
  datasets: [] as Dataset[],
  privacyThresholds: [] as any[],
  statisticalFidelityTargets: [] as any[]
});

const allowedFieldsInput = ref<Record<string, string>>({});
const requiredFiltersInput = ref<Record<string, Filter[]>>({});

watch(() => props.editingSuite, (suite) => {
  if (suite) {
    // Determine testType from suite (check testType first, then infer from old structure)
    let testType = suite.testType;
    if (!testType) {
      // Backward compatibility: infer from old boolean flags
      if (suite.includeAccessControlTests) testType = 'access-control';
      else if (suite.includeDatasetHealthTests) testType = 'dataset-health';
      else testType = 'access-control'; // default
    }

    form.value = {
      name: suite.name || '',
      application: suite.application || suite.applicationId || '',
      team: suite.team || '',
      testType: testType,
      userRoles: suite.userRoles || [],
      resources: suite.resources || [],
      contexts: suite.contexts || [],
      expectedDecisions: suite.expectedDecisions || {},
      testQueries: suite.testQueries || [],
      allowedFields: suite.allowedFields || {},
      requiredFilters: suite.requiredFilters || {},
      datasets: suite.datasets || [],
      privacyThresholds: suite.privacyThresholds || [],
      statisticalFidelityTargets: suite.statisticalFidelityTargets || []
    };
    
    // Initialize input fields
    form.value.userRoles.forEach(role => {
      allowedFieldsInput.value[role] = (suite.allowedFields?.[role] || []).join(', ');
      requiredFiltersInput.value[role] = suite.requiredFilters?.[role] || [];
    });
  } else {
    resetForm();
  }
}, { immediate: true });

watch(() => props.show, (show) => {
  if (!show) {
    resetForm();
  }
});

function resetForm() {
  form.value = {
    name: '',
    application: '',
    team: '',
    testType: '',
    userRoles: [],
    resources: [],
    contexts: [],
    expectedDecisions: {},
    testQueries: [],
    allowedFields: {},
    requiredFilters: {},
    datasets: [],
    privacyThresholds: [],
    statisticalFidelityTargets: []
  };
  allowedFieldsInput.value = {};
  requiredFiltersInput.value = {};
  newRole.value = '';
  activeTab.value = 'basic';
}

function addRole() {
  if (newRole.value.trim() && !form.value.userRoles.includes(newRole.value.trim())) {
    form.value.userRoles.push(newRole.value.trim());
    newRole.value = '';
  }
}

function removeRole(index: number) {
  const role = form.value.userRoles[index];
  form.value.userRoles.splice(index, 1);
  delete allowedFieldsInput.value[role];
  delete requiredFiltersInput.value[role];
  delete form.value.allowedFields[role];
  delete form.value.requiredFilters[role];
}

function addResource() {
  form.value.resources.push({
    id: '',
    type: '',
    sensitivity: ''
  });
}

function removeResource(index: number) {
  form.value.resources.splice(index, 1);
}

function addContext() {
  form.value.contexts.push({
    ipAddress: '',
    timeOfDay: '',
    location: ''
  });
}

function removeContext(index: number) {
  form.value.contexts.splice(index, 1);
}

function addQuery() {
  form.value.testQueries.push({
    name: '',
    sql: '',
    apiEndpoint: '',
    httpMethod: ''
  });
}

function removeQuery(index: number) {
  form.value.testQueries.splice(index, 1);
}

function addFilter(role: string) {
  if (!requiredFiltersInput.value[role]) {
    requiredFiltersInput.value[role] = [];
  }
  requiredFiltersInput.value[role].push({
    field: '',
    operator: '=',
    value: ''
  });
}

function removeFilter(role: string, index: number) {
  requiredFiltersInput.value[role].splice(index, 1);
}


function addDataset() {
  form.value.datasets.push({
    name: '',
    type: 'raw'
  });
}

function removeDataset(index: number) {
  form.value.datasets.splice(index, 1);
}

function close() {
  emit('close');
}

function save() {
  if (!form.value.testType) {
    alert('Please select a test type');
    return;
  }

  // Process allowed fields
  const allowedFields: Record<string, string[]> = {};
  form.value.userRoles.forEach(role => {
    const input = allowedFieldsInput.value[role];
    if (input) {
      allowedFields[role] = input.split(',').map(f => f.trim()).filter(f => f);
    }
  });
  form.value.allowedFields = allowedFields;

  // Process required filters
  form.value.requiredFilters = requiredFiltersInput.value;

  // Build suite object based on testType
  const suiteData: any = {
    name: form.value.name,
    application: form.value.application,
    team: form.value.team,
    testType: form.value.testType,
    userRoles: form.value.userRoles,
    resources: form.value.resources,
    contexts: form.value.contexts,
  };

  // Add type-specific fields
  if (form.value.testType === 'access-control') {
    suiteData.expectedDecisions = form.value.expectedDecisions;
  } else if (form.value.testType === 'dataset-health') {
    suiteData.datasets = form.value.datasets;
    suiteData.privacyThresholds = form.value.privacyThresholds;
    suiteData.statisticalFidelityTargets = form.value.statisticalFidelityTargets;
  }

  emit('save', suiteData);
}

function saveAsDraft() {
  save();
  emit('saveDraft', { ...form.value });
}
</script>

<style scoped>
.large-modal {
  max-width: 900px;
  max-height: 90vh;
}

.typescript-warning {
  display: flex;
  gap: 12px;
  padding: 16px;
  margin-bottom: 20px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
  color: #fbbf24;
}

.warning-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.warning-content {
  flex: 1;
}

.warning-content strong {
  display: block;
  margin-bottom: 4px;
  color: #fbbf24;
}

.warning-content p {
  margin: 0;
  font-size: 0.875rem;
  color: #fcd34d;
  line-height: 1.5;
}

.builder-tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  overflow-x: auto;
}

.builder-tab {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 10px 16px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  white-space: nowrap;
  transition: all 0.2s;
}

.builder-tab:hover {
  color: #4facfe;
}

.builder-tab.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.tab-panel {
  min-height: 300px;
  max-height: 500px;
  overflow-y: auto;
  padding-right: 8px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.section-header h3 {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-small {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 48px;
}

.tag {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
}

.tag-remove {
  display: flex;
  align-items: center;
  padding: 2px;
  background: transparent;
  border: none;
  cursor: pointer;
  color: #4facfe;
  transition: color 0.2s;
}

.tag-remove:hover {
  color: #fc8181;
}

.tag-icon {
  width: 12px;
  height: 12px;
}

.tag-input {
  flex: 1;
  min-width: 150px;
  background: transparent;
  border: none;
  color: #ffffff;
  font-size: 0.9rem;
  outline: none;
}

.resource-item,
.context-item,
.query-item,
.contract-item,
.dataset-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  margin-bottom: 12px;
}

.btn-icon-only {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 8px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  color: #fc8181;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-icon-only:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.btn-icon-only .icon {
  width: 16px;
  height: 16px;
}

.code-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.role-fields,
.role-filters {
  margin-bottom: 20px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.role-fields h4,
.role-filters h4 {
  font-size: 0.9rem;
  font-weight: 600;
  color: #4facfe;
  margin: 0 0 12px 0;
}

.filter-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
}

.filter-row input,
.filter-row select {
  flex: 1;
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

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  position: sticky;
  top: 0;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  z-index: 10;
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

.suite-form {
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
.form-group select,
.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234facfe' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  padding-right: 40px;
}

.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  align-items: end;
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
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.info-message {
  padding: 1rem;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  text-align: center;
}

.decisions-grid {
  display: grid;
  gap: 1.5rem;
}

.role-decisions {
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.role-decisions h4 {
  margin: 0 0 1rem 0;
  font-size: 1rem;
  font-weight: 600;
  color: #4facfe;
}

.decision-item {
  margin-bottom: 0.75rem;
}

.decision-label {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 1rem;
}

.resource-name {
  flex: 1;
  color: #ffffff;
  font-size: 0.875rem;
}

.decision-select {
  padding: 0.5rem 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  min-width: 120px;
}
</style>

