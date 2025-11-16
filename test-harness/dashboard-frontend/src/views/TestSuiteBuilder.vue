<template>
  <div class="test-suite-builder">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="builder-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">{{ editingSuite ? 'Edit Test Suite' : 'Create Test Suite' }}</h1>
          <p class="page-description">Step-by-step wizard to configure your compliance test suite</p>
        </div>
        <div class="header-actions">
          <button @click="saveDraft" class="btn-secondary" :disabled="saving">
            <Save class="btn-icon" />
            {{ saving ? 'Saving...' : 'Save Draft' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Progress Indicator -->
    <div class="wizard-progress">
      <div
        v-for="(step, index) in steps"
        :key="step.id"
        class="progress-step"
        :class="{
          active: currentStep === index,
          completed: currentStep > index,
          disabled: !canAccessStep(index)
        }"
        @click="goToStep(index)"
      >
        <div class="step-number">
          <Check v-if="currentStep > index" class="check-icon" />
          <span v-else>{{ index + 1 }}</span>
        </div>
        <div class="step-info">
          <div class="step-title">{{ step.title }}</div>
          <div class="step-description">{{ step.description }}</div>
        </div>
      </div>
    </div>

    <!-- Wizard Content -->
    <div class="wizard-content">
      <div class="wizard-card">
        <!-- Step 1: Basic Information -->
        <div v-if="currentStep === 0" class="wizard-step">
          <h2 class="step-heading">Basic Information</h2>
          <p class="step-subheading">Provide basic details about your test suite</p>
          
          <div class="form-section">
            <div class="form-group">
              <label>Test Suite Name *</label>
              <input
                v-model="form.name"
                type="text"
                placeholder="e.g., Research Tracker API Compliance Tests"
                required
                class="form-input"
              />
            </div>
            
            <div class="form-row">
              <div class="form-group">
                <label>Application *</label>
                <input
                  v-model="form.application"
                  type="text"
                  placeholder="e.g., research-tracker-api"
                  required
                  class="form-input"
                />
              </div>
              <div class="form-group">
                <label>Team *</label>
                <input
                  v-model="form.team"
                  type="text"
                  placeholder="e.g., research-platform"
                  required
                  class="form-input"
                />
              </div>
            </div>

            <div class="form-group">
              <label>Test Type *</label>
              <p class="form-help">Select the type of tests for this suite. Each suite must have exactly one test type.</p>
              <select v-model="form.testType" required class="form-input form-select">
                <option value="">Select a test type...</option>
                <option value="access-control">Access Control</option>
                <option value="data-behavior">Data Behavior</option>
                <option value="contract">Contract</option>
                <option value="dataset-health">Dataset Health</option>
                <option value="rls-cls">RLS/CLS</option>
                <option value="network-policy">Network Policy</option>
                <option value="dlp">DLP</option>
                <option value="api-gateway">API Gateway</option>
                <option value="distributed-systems">Distributed Systems</option>
                <option value="api-security">API Security</option>
                <option value="data-pipeline">Data Pipeline</option>
              </select>
            </div>
          </div>
        </div>

        <!-- Step 2: User Roles & Attributes -->
        <div v-if="currentStep === 1" class="wizard-step">
          <h2 class="step-heading">User Roles & Attributes</h2>
          <p class="step-subheading">Define user roles and attributes to test</p>
          
          <div class="form-section">
            <div class="form-group">
              <label>User Roles *</label>
              <p class="form-help">Add roles that will be tested (e.g., admin, researcher, viewer)</p>
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
        </div>

        <!-- Step 3: Resources -->
        <div v-if="currentStep === 2" class="wizard-step">
          <h2 class="step-heading">Resources</h2>
          <p class="step-subheading">Define resources to test access against</p>
          
          <div class="form-section">
            <div class="section-actions">
              <button @click="showAddResource = true" type="button" class="btn-add">
                <Plus class="btn-icon" />
                Add Resource
              </button>
            </div>
            
            <div v-if="form.resources.length === 0" class="empty-state-small">
              <Database class="empty-icon" />
              <p>No resources added yet</p>
            </div>
            
            <div v-else class="resources-list">
              <div
                v-for="(resource, index) in form.resources"
                :key="index"
                class="resource-card"
              >
                <div class="resource-header">
                  <div>
                    <h4>{{ resource.id }}</h4>
                    <span class="resource-type">{{ resource.type }}</span>
                  </div>
                  <div class="resource-actions">
                    <button @click="editResource(index)" type="button" class="icon-btn">
                      <Edit class="icon" />
                    </button>
                    <button @click="removeResource(index)" type="button" class="icon-btn">
                      <Trash2 class="icon" />
                    </button>
                  </div>
                </div>
                <div class="resource-details">
                  <div v-if="resource.sensitivity" class="detail-item">
                    <span class="detail-label">Sensitivity:</span>
                    <span class="detail-value">{{ resource.sensitivity }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Step 4: Contexts -->
        <div v-if="currentStep === 3" class="wizard-step">
          <h2 class="step-heading">Contexts</h2>
          <p class="step-subheading">Define contexts for testing (IP address, time, location)</p>
          
          <div class="form-section">
            <div class="section-actions">
              <button @click="showAddContext = true" type="button" class="btn-add">
                <Plus class="btn-icon" />
                Add Context
              </button>
            </div>
            
            <div v-if="form.contexts.length === 0" class="empty-state-small">
              <Globe class="empty-icon" />
              <p>No contexts added yet</p>
            </div>
            
            <div v-else class="contexts-list">
              <div
                v-for="(context, index) in form.contexts"
                :key="index"
                class="context-card"
              >
                <div class="context-header">
                  <div>
                    <h4>Context {{ index + 1 }}</h4>
                  </div>
                  <button @click="removeContext(index)" type="button" class="icon-btn">
                    <Trash2 class="icon" />
                  </button>
                </div>
                <div class="context-details">
                  <div v-if="context.ipAddress" class="detail-item">
                    <span class="detail-label">IP:</span>
                    <span class="detail-value">{{ context.ipAddress }}</span>
                  </div>
                  <div v-if="context.location" class="detail-item">
                    <span class="detail-label">Location:</span>
                    <span class="detail-value">{{ context.location }}</span>
                  </div>
                  <div v-if="context.timeOfDay" class="detail-item">
                    <span class="detail-label">Time:</span>
                    <span class="detail-value">{{ context.timeOfDay }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Step 5: Test Type Configurations -->
        <div v-if="currentStep === 4" class="wizard-step">
          <h2 class="step-heading">Test Type Configurations</h2>
          <p class="step-subheading">Configure specific settings for the selected test type</p>
          
          <div v-if="!form.testType" class="form-section">
            <div class="empty-state-small">
              <p>Please select a test type in Step 1 to configure settings.</p>
            </div>
          </div>
          
          <div v-else class="form-section">
            <!-- Access Control Configuration -->
            <div v-if="form.testType === 'access-control'" class="config-section">
              <h3 class="config-title">
                <Shield class="config-icon" />
                Access Control Tests
              </h3>
              <div class="form-group">
                <label>Expected Decisions</label>
                <p class="form-help">Define expected access decisions for role-resource combinations</p>
                <div class="expected-decisions">
                  <div
                    v-for="(decision, key) in form.expectedDecisions"
                    :key="key"
                    class="decision-item"
                  >
                    <span class="decision-key">{{ key }}</span>
                    <select v-model="form.expectedDecisions[key]" class="decision-select">
                      <option :value="true">Allow</option>
                      <option :value="false">Deny</option>
                    </select>
                    <button @click="removeExpectedDecision(key)" type="button" class="icon-btn-small">
                      <X class="icon" />
                    </button>
                  </div>
                  <button @click="showAddExpectedDecision = true" type="button" class="btn-add-small">
                    <Plus class="btn-icon" />
                    Add Expected Decision
                  </button>
                </div>
              </div>
            </div>

            <!-- Data Behavior Configuration -->
            <div v-if="form.testType === 'data-behavior'" class="config-section">
              <h3 class="config-title">
                <Database class="config-icon" />
                Data Behavior Tests
              </h3>
              <div class="form-group">
                <label>Test Queries</label>
                <p class="form-help">Define SQL queries to test</p>
                <div class="queries-list">
                  <div
                    v-for="(query, index) in form.testQueries"
                    :key="index"
                    class="query-card"
                  >
                    <div class="query-header">
                      <input
                        v-model="query.name"
                        type="text"
                        placeholder="Query name"
                        class="query-name-input"
                      />
                      <button @click="removeQuery(index)" type="button" class="icon-btn">
                        <Trash2 class="icon" />
                      </button>
                    </div>
                    <textarea
                      v-model="query.sql"
                      placeholder="SELECT * FROM ..."
                      rows="3"
                      class="query-sql-input"
                    ></textarea>
                  </div>
                  <button @click="addQuery" type="button" class="btn-add-small">
                    <Plus class="btn-icon" />
                    Add Query
                  </button>
                </div>
              </div>
              
              <div class="form-group">
                <label>Allowed Fields</label>
                <p class="form-help">Define which fields each role can access</p>
                <div class="allowed-fields">
                  <div
                    v-for="(fields, role) in form.allowedFields"
                    :key="role"
                    class="fields-item"
                  >
                    <div class="fields-header">
                      <span class="fields-role">{{ role }}</span>
                      <button @click="removeAllowedFields(role)" type="button" class="icon-btn-small">
                        <X class="icon" />
                      </button>
                    </div>
                    <div class="tags-input">
                      <span
                        v-for="(field, idx) in fields"
                        :key="idx"
                        class="tag"
                      >
                        {{ field }}
                        <button @click="removeField(role, idx)" type="button" class="tag-remove">
                          <X class="tag-icon" />
                        </button>
                      </span>
                      <input
                        v-model="newFields[role]"
                        type="text"
                        placeholder="Add field and press Enter"
                        @keydown.enter.prevent="addField(role)"
                        class="tag-input"
                      />
                    </div>
                  </div>
                  <button @click="showAddAllowedFields = true" type="button" class="btn-add-small">
                    <Plus class="btn-icon" />
                    Add Role Fields
                  </button>
                </div>
              </div>
            </div>

            <!-- Contract Configuration -->
            <div v-if="form.testType === 'contract'" class="config-section">
              <h3 class="config-title">
                <FileText class="config-icon" />
                Contract Tests
              </h3>
              <div class="form-group">
                <label>Contracts</label>
                <p class="form-help">Define data owner contracts</p>
                <div class="contracts-list">
                  <div
                    v-for="(contract, index) in form.contracts"
                    :key="index"
                    class="contract-card"
                  >
                    <div class="contract-header">
                      <div>
                        <h4>{{ contract.name }}</h4>
                        <span class="contract-owner">{{ contract.dataOwner }}</span>
                      </div>
                      <button @click="removeContract(index)" type="button" class="icon-btn">
                        <Trash2 class="icon" />
                      </button>
                    </div>
                  </div>
                  <button @click="showAddContract = true" type="button" class="btn-add-small">
                    <Plus class="btn-icon" />
                    Add Contract
                  </button>
                </div>
              </div>
            </div>

            <!-- Dataset Health Configuration -->
            <div v-if="form.testType === 'dataset-health'" class="config-section">
              <h3 class="config-title">
                <Activity class="config-icon" />
                Dataset Health Tests
              </h3>
              <div class="form-group">
                <label>Datasets</label>
                <p class="form-help">Define datasets to test</p>
                <div class="datasets-list">
                  <div
                    v-for="(dataset, index) in form.datasets"
                    :key="index"
                    class="dataset-card"
                  >
                    <div class="dataset-header">
                      <div>
                        <h4>{{ dataset.name }}</h4>
                        <span class="dataset-type">{{ dataset.type }}</span>
                      </div>
                      <button @click="removeDataset(index)" type="button" class="icon-btn">
                        <Trash2 class="icon" />
                      </button>
                    </div>
                  </div>
                  <button @click="showAddDataset = true" type="button" class="btn-add-small">
                    <Plus class="btn-icon" />
                    Add Dataset
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Step 6: Preview & Validation -->
        <div v-if="currentStep === 5" class="wizard-step">
          <h2 class="step-heading">Preview & Validation</h2>
          <p class="step-subheading">Review your test suite configuration</p>
          
          <div class="form-section">
            <div class="preview-container">
              <div class="preview-section">
                <h3>Basic Information</h3>
                <div class="preview-item">
                  <span class="preview-label">Name:</span>
                  <span class="preview-value">{{ form.name || 'Not set' }}</span>
                </div>
                <div class="preview-item">
                  <span class="preview-label">Application:</span>
                  <span class="preview-value">{{ form.application || 'Not set' }}</span>
                </div>
                <div class="preview-item">
                  <span class="preview-label">Team:</span>
                  <span class="preview-value">{{ form.team || 'Not set' }}</span>
                </div>
                <div class="preview-item">
                  <span class="preview-label">Test Type:</span>
                  <span class="preview-value">{{ form.testType || 'Not set' }}</span>
                </div>
              </div>

              <div class="preview-section">
                <h3>Configuration Summary</h3>
                <div class="preview-item">
                  <span class="preview-label">User Roles:</span>
                  <span class="preview-value">{{ form.userRoles.length }} roles</span>
                </div>
                <div class="preview-item">
                  <span class="preview-label">Resources:</span>
                  <span class="preview-value">{{ form.resources.length }} resources</span>
                </div>
                <div class="preview-item">
                  <span class="preview-label">Contexts:</span>
                  <span class="preview-value">{{ form.contexts.length }} contexts</span>
                </div>
                <div v-if="form.testQueries" class="preview-item">
                  <span class="preview-label">Test Queries:</span>
                  <span class="preview-value">{{ form.testQueries.length }} queries</span>
                </div>
              </div>
            </div>

            <!-- Validation Results -->
            <div class="validation-section">
              <h3>Validation</h3>
              <div v-if="validationErrors.length > 0" class="validation-errors">
                <AlertTriangle class="error-icon" />
                <div>
                  <h4>Validation Errors</h4>
                  <ul>
                    <li v-for="(error, index) in validationErrors" :key="index">{{ error }}</li>
                  </ul>
                </div>
              </div>
              <div v-else class="validation-success">
                <CheckCircle2 class="success-icon" />
                <span>All validations passed! Your test suite is ready to be saved.</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Navigation Buttons -->
        <div class="wizard-actions">
          <button
            v-if="currentStep > 0"
            @click="previousStep"
            type="button"
            class="btn-secondary"
          >
            <ChevronLeft class="btn-icon" />
            Previous
          </button>
          <div class="spacer"></div>
          <button
            v-if="currentStep < steps.length - 1"
            @click="nextStep"
            type="button"
            class="btn-primary"
            :disabled="!canProceed"
          >
            Next
            <ChevronRight class="btn-icon" />
          </button>
          <button
            v-if="currentStep === steps.length - 1"
            @click="publish"
            type="button"
            class="btn-primary"
            :disabled="!canPublish || saving"
          >
            <Check class="btn-icon" />
            {{ saving ? 'Publishing...' : 'Publish Test Suite' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Modals -->
    <AddResourceModal
      v-if="showAddResource"
      :show="showAddResource"
      :resource="editingResourceIndex !== null ? form.resources[editingResourceIndex] : null"
      @close="closeResourceModal"
      @save="saveResource"
    />
    
    <AddContextModal
      v-if="showAddContext"
      :show="showAddContext"
      @close="closeContextModal"
      @save="saveContext"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import {
  TestTube,
  Shield,
  Users,
  Database,
  Globe,
  Settings,
  Eye,
  Check,
  ChevronLeft,
  ChevronRight,
  Plus,
  X,
  Edit,
  Trash2,
  Save,
  FileText,
  Activity,
  AlertTriangle,
  CheckCircle2
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import AddResourceModal from '../components/AddResourceModal.vue';
import AddContextModal from '../components/AddContextModal.vue';

const router = useRouter();
const route = useRoute();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Builder' }
];

const currentStep = ref(0);
const saving = ref(false);
const newRole = ref('');
const newFields = ref<Record<string, string>>({});
const showAddResource = ref(false);
const showAddContext = ref(false);
const editingResourceIndex = ref<number | null>(null);
const editingSuite = ref<string | null>(null);

const steps = [
  { id: 'basic', title: 'Basic Information', description: 'Name and test types' },
  { id: 'users', title: 'User Roles', description: 'Define roles and attributes' },
  { id: 'resources', title: 'Resources', description: 'Define test resources' },
  { id: 'contexts', title: 'Contexts', description: 'Define test contexts' },
  { id: 'config', title: 'Configuration', description: 'Configure test types' },
  { id: 'preview', title: 'Preview', description: 'Review and validate' }
];

const form = ref({
  name: '',
  application: '',
  team: '',
  testType: '' as string,
  userRoles: [] as string[],
  resources: [] as any[],
  contexts: [] as any[],
  expectedDecisions: {} as Record<string, boolean>,
  testQueries: [] as Array<{ name: string; sql?: string }>,
  allowedFields: {} as Record<string, string[]>,
  contracts: [] as any[],
  datasets: [] as any[]
});

const canProceed = computed(() => {
  switch (currentStep.value) {
    case 0:
      return form.value.name && form.value.application && form.value.team && form.value.testType;
    case 1:
      return form.value.userRoles.length > 0;
    default:
      return true;
  }
});

const canPublish = computed(() => {
  return validationErrors.value.length === 0 && canProceed.value;
});

const validationErrors = computed(() => {
  const errors: string[] = [];
  
  if (!form.value.name) errors.push('Test suite name is required');
  if (!form.value.application) errors.push('Application is required');
  if (!form.value.team) errors.push('Team is required');
  
  if (!form.value.testType) {
    errors.push('Test type must be selected');
  }
  
  if (form.value.userRoles.length === 0) {
    errors.push('At least one user role is required');
  }
  
  if (form.value.testType === 'access-control' && form.value.resources.length === 0) {
    errors.push('At least one resource is required for access control tests');
  }
  
  return errors;
});

const canAccessStep = (stepIndex: number): boolean => {
  if (stepIndex === 0) return true;
  if (stepIndex === 1) return canProceed.value;
  return currentStep.value >= stepIndex - 1;
};

const nextStep = () => {
  if (canProceed.value && currentStep.value < steps.length - 1) {
    currentStep.value++;
  }
};

const previousStep = () => {
  if (currentStep.value > 0) {
    currentStep.value--;
  }
};

const goToStep = (stepIndex: number) => {
  if (canAccessStep(stepIndex)) {
    currentStep.value = stepIndex;
  }
};

const addRole = () => {
  if (newRole.value.trim() && !form.value.userRoles.includes(newRole.value.trim())) {
    form.value.userRoles.push(newRole.value.trim());
    newRole.value = '';
  }
};

const removeRole = (index: number) => {
  form.value.userRoles.splice(index, 1);
};

const saveResource = (resource: any) => {
  if (editingResourceIndex.value !== null) {
    form.value.resources[editingResourceIndex.value] = resource;
    editingResourceIndex.value = null;
  } else {
    form.value.resources.push(resource);
  }
  showAddResource.value = false;
};

const editResource = (index: number) => {
  editingResourceIndex.value = index;
  showAddResource.value = true;
};

const removeResource = (index: number) => {
  form.value.resources.splice(index, 1);
};

const closeResourceModal = () => {
  showAddResource.value = false;
  editingResourceIndex.value = null;
};

const saveContext = (context: any) => {
  form.value.contexts.push(context);
  showAddContext.value = false;
};

const closeContextModal = () => {
  showAddContext.value = false;
};

const removeContext = (index: number) => {
  form.value.contexts.splice(index, 1);
};

const addQuery = () => {
  form.value.testQueries.push({ name: '', sql: '' });
};

const removeQuery = (index: number) => {
  form.value.testQueries.splice(index, 1);
};

const addField = (role: string) => {
  if (!form.value.allowedFields[role]) {
    form.value.allowedFields[role] = [];
  }
  if (newFields.value[role]?.trim() && !form.value.allowedFields[role].includes(newFields.value[role].trim())) {
    form.value.allowedFields[role].push(newFields.value[role].trim());
    newFields.value[role] = '';
  }
};

const removeField = (role: string, index: number) => {
  form.value.allowedFields[role].splice(index, 1);
};

const removeAllowedFields = (role: string) => {
  delete form.value.allowedFields[role];
};

const removeContract = (index: number) => {
  form.value.contracts.splice(index, 1);
};

const removeDataset = (index: number) => {
  form.value.datasets.splice(index, 1);
};

const removeExpectedDecision = (key: string) => {
  delete form.value.expectedDecisions[key];
};

const saveDraft = async () => {
  if (!form.value.testType) {
    alert('Please select a test type');
    return;
  }

  saving.value = true;
  try {
    // Build type-specific suite object
    const suiteData: any = {
      name: form.value.name,
      application: form.value.application,
      team: form.value.team,
      testType: form.value.testType,
      userRoles: form.value.userRoles,
      resources: form.value.resources,
      contexts: form.value.contexts,
      status: 'draft'
    };

    // Add type-specific fields
    if (form.value.testType === 'access-control') {
      suiteData.expectedDecisions = form.value.expectedDecisions;
    } else if (form.value.testType === 'data-behavior') {
      suiteData.testQueries = form.value.testQueries;
      suiteData.allowedFields = form.value.allowedFields;
    } else if (form.value.testType === 'contract') {
      suiteData.contracts = form.value.contracts;
    } else if (form.value.testType === 'dataset-health') {
      suiteData.datasets = form.value.datasets;
    }

    await axios.post('/api/test-suites', suiteData);
    // In a real app, show success message
  } catch (error) {
    console.error('Error saving draft:', error);
    alert('Failed to save draft. Please check the console for details.');
  } finally {
    saving.value = false;
  }
};

const publish = async () => {
  if (!canPublish.value) return;
  if (!form.value.testType) {
    alert('Please select a test type');
    return;
  }
  
  saving.value = true;
  try {
    // Build type-specific suite object
    const suiteData: any = {
      name: form.value.name,
      application: form.value.application,
      team: form.value.team,
      testType: form.value.testType,
      userRoles: form.value.userRoles,
      resources: form.value.resources,
      contexts: form.value.contexts,
      status: 'published'
    };

    // Add type-specific fields
    if (form.value.testType === 'access-control') {
      suiteData.expectedDecisions = form.value.expectedDecisions;
    } else if (form.value.testType === 'data-behavior') {
      suiteData.testQueries = form.value.testQueries;
      suiteData.allowedFields = form.value.allowedFields;
    } else if (form.value.testType === 'contract') {
      suiteData.contracts = form.value.contracts;
    } else if (form.value.testType === 'dataset-health') {
      suiteData.datasets = form.value.datasets;
    }

    await axios.post('/api/test-suites', suiteData);
    router.push('/tests');
  } catch (error) {
    console.error('Error publishing test suite:', error);
    alert('Failed to publish test suite. Please check the console for details.');
  } finally {
    saving.value = false;
  }
};

onMounted(() => {
  // Check if editing
  const suiteId = route.params.id;
  if (suiteId) {
    editingSuite.value = suiteId as string;
    // Load suite data
    // In a real app, fetch from API
  }
});
</script>

<style scoped>
.test-suite-builder {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
}

.builder-header {
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

.header-actions {
  display: flex;
  gap: 12px;
}

.wizard-progress {
  display: flex;
  gap: 16px;
  margin-bottom: 32px;
  overflow-x: auto;
  padding-bottom: 16px;
}

.progress-step {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s;
  min-width: 200px;
  flex-shrink: 0;
}

.progress-step:hover:not(.disabled) {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.progress-step.active {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.progress-step.completed {
  border-color: #22c55e;
  background: rgba(34, 197, 94, 0.1);
}

.progress-step.disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.step-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  flex-shrink: 0;
}

.progress-step.active .step-number {
  background: #4facfe;
  color: #0f1419;
}

.progress-step.completed .step-number {
  background: #22c55e;
  color: #ffffff;
}

.check-icon {
  width: 18px;
  height: 18px;
}

.step-info {
  flex: 1;
}

.step-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 4px;
}

.step-description {
  font-size: 0.75rem;
  color: #a0aec0;
}

.wizard-content {
  margin-bottom: 32px;
}

.wizard-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
}

.wizard-step {
  min-height: 400px;
}

.step-heading {
  font-size: 1.75rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.step-subheading {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 32px;
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: 24px;
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

.form-help {
  font-size: 0.75rem;
  color: #718096;
  margin: 0;
}

.form-input {
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
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

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.test-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 16px;
  margin-top: 12px;
}

.test-type-card {
  display: flex;
  align-items: flex-start;
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 2px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  cursor: pointer;
  transition: all 0.2s;
}

.test-type-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.test-type-card.selected {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.test-type-checkbox {
  margin-right: 12px;
  margin-top: 4px;
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.test-type-content {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.test-type-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 2px;
}

.test-type-info {
  flex: 1;
}

.test-type-name {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 4px;
}

.test-type-desc {
  font-size: 0.75rem;
  color: #a0aec0;
  line-height: 1.4;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  min-height: 48px;
}

.tag {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.tag-remove {
  background: transparent;
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
  min-width: 150px;
  background: transparent;
  border: none;
  color: #ffffff;
  font-size: 0.875rem;
  outline: none;
}

.section-actions {
  margin-bottom: 16px;
}

.btn-add,
.btn-add-small {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-add-small {
  padding: 8px 12px;
  font-size: 0.8rem;
}

.btn-add:hover,
.btn-add-small:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.empty-state-small {
  text-align: center;
  padding: 40px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px dashed rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.resources-list,
.contexts-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.resource-card,
.context-card {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.resource-header,
.context-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.resource-header h4,
.context-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.resource-type {
  padding: 4px 8px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.resource-actions {
  display: flex;
  gap: 8px;
}

.icon-btn {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
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

.icon-btn .icon {
  width: 16px;
  height: 16px;
}

.icon-btn-small {
  padding: 4px;
  background: transparent;
  border: none;
  color: #4facfe;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-btn-small .icon {
  width: 14px;
  height: 14px;
}

.resource-details,
.context-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
}

.detail-item {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.detail-label {
  color: #718096;
  font-weight: 500;
}

.detail-value {
  color: #ffffff;
}

.config-section {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  margin-bottom: 24px;
}

.config-title {
  display: flex;
  align-items: center;
  gap: 12px;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.config-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.queries-list,
.contracts-list,
.datasets-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.query-card,
.contract-card,
.dataset-card {
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.query-header {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}

.query-name-input {
  flex: 1;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
}

.query-sql-input {
  width: 100%;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
  resize: vertical;
}

.allowed-fields {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.fields-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.fields-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.fields-role {
  font-weight: 600;
  color: #4facfe;
  font-size: 0.9rem;
}

.expected-decisions {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.decision-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
}

.decision-key {
  flex: 1;
  color: #ffffff;
  font-size: 0.875rem;
}

.decision-select {
  padding: 6px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  cursor: pointer;
}

.preview-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.preview-section {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.preview-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.preview-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.preview-item:last-child {
  border-bottom: none;
}

.preview-label {
  color: #718096;
  font-size: 0.875rem;
}

.preview-value {
  color: #ffffff;
  font-weight: 500;
}

.preview-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.preview-badge {
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 500;
}

.validation-section {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.validation-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.validation-errors {
  display: flex;
  gap: 12px;
  padding: 16px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
}

.error-icon {
  width: 24px;
  height: 24px;
  color: #fc8181;
  flex-shrink: 0;
}

.validation-errors h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #fc8181;
  margin: 0 0 8px 0;
}

.validation-errors ul {
  margin: 0;
  padding-left: 20px;
  color: #fc8181;
}

.validation-errors li {
  margin-bottom: 4px;
}

.validation-success {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 16px;
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 8px;
  color: #22c55e;
}

.success-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
}

.wizard-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.spacer {
  flex: 1;
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

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}
</style>

