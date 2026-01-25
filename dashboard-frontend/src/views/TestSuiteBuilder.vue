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
                <option value="network-policy">Network Policy</option>
                <option value="dlp">Data Loss Prevention (DLP)</option>
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
    } else if (form.value.testType === 'contract') {
      suiteData.contracts = form.value.contracts;
    } else if (form.value.testType === 'dataset-health') {
      suiteData.datasets = form.value.datasets;
    }

    await axios.post('/api/v1/test-suites', suiteData);
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
    } else if (form.value.testType === 'contract') {
      suiteData.contracts = form.value.contracts;
    } else if (form.value.testType === 'dataset-health') {
      suiteData.datasets = form.value.datasets;
    }

    await axios.post('/api/v1/test-suites', suiteData);
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
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.wizard-progress {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
  overflow-x: auto;
  padding-bottom: var(--spacing-md);
}

.progress-step {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  cursor: pointer;
  transition: var(--transition-all);
  min-width: 200px;
  flex-shrink: 0;
}

.progress-step:hover:not(.disabled) {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
}

.progress-step.active {
  border-color: var(--color-primary);
  background: var(--color-info-bg);
}

.progress-step.completed {
  border-color: var(--color-success);
  background: var(--color-success-bg);
}

.progress-step.disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.step-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--color-info-bg);
  color: var(--color-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: var(--font-weight-semibold);
  flex-shrink: 0;
}

.progress-step.active .step-number {
  background: var(--color-primary);
  color: var(--color-bg-primary);
}

.progress-step.completed .step-number {
  background: var(--color-success);
  color: var(--color-text-primary);
}

.check-icon {
  width: 18px;
  height: 18px;
}

.step-info {
  flex: 1;
}

.step-title {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.step-description {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.wizard-content {
  margin-bottom: var(--spacing-xl);
}

.wizard-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-xl);
}

.wizard-step {
  min-height: 400px;
}

.step-heading {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.step-subheading {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xl);
}

.form-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-help {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: 0;
}

.form-input {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
}

.form-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--color-info-bg);
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
  gap: var(--spacing-md);
}

.test-types-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-md);
  margin-top: var(--spacing-sm);
}

.test-type-card {
  display: flex;
  align-items: flex-start;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-medium) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.test-type-card:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
}

.test-type-card.selected {
  border-color: var(--color-primary);
  background: var(--color-info-bg);
}

.test-type-checkbox {
  margin-right: var(--spacing-sm);
  margin-top: var(--spacing-xs);
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.test-type-content {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  flex: 1;
}

.test-type-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
  margin-top: 2px;
}

.test-type-info {
  flex: 1;
}

.test-type-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.test-type-desc {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  line-height: 1.4;
}

.tags-input {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  min-height: 48px;
}

.tag {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.tag-remove {
  background: transparent;
  border: none;
  color: var(--color-primary);
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
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  outline: none;
}

.section-actions {
  margin-bottom: 16px;
}

.btn-add,
.btn-add-small {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-info-bg);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-add-small {
  padding: var(--spacing-sm) var(--spacing-sm);
  font-size: var(--font-size-xs);
}

.btn-add:hover,
.btn-add-small:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.empty-state-small {
  text-align: center;
  padding: var(--spacing-2xl);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) dashed var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.resources-list,
.contexts-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.resource-card,
.context-card {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.resource-header,
.context-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.resource-header h4,
.context-header h4 {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.resource-type {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-xs);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.resource-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.icon-btn {
  padding: var(--spacing-xs);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  cursor: pointer;
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-btn:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-hover);
}

.icon-btn .icon {
  width: 16px;
  height: 16px;
}

.icon-btn-small {
  padding: var(--spacing-xs);
  background: transparent;
  border: none;
  color: var(--color-primary);
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
  gap: var(--spacing-md);
}

.detail-item {
  display: flex;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.detail-label {
  color: var(--color-text-muted);
  font-weight: var(--font-weight-medium);
}

.detail-value {
  color: var(--color-text-primary);
}

.config-section {
  padding: var(--spacing-xl);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-lg);
}

.config-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.config-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
}

.queries-list,
.contracts-list,
.datasets-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.query-card,
.contract-card,
.dataset-card {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.query-header {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.query-name-input {
  flex: 1;
  padding: var(--spacing-sm) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.query-sql-input {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-family: 'Courier New', monospace;
  resize: vertical;
}

.allowed-fields {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.fields-item {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.fields-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.fields-role {
  font-weight: var(--font-weight-semibold);
  color: var(--color-primary);
  font-size: var(--font-size-base);
}

.expected-decisions {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.decision-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
}

.decision-key {
  flex: 1;
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.decision-select {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
}

.preview-container {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.preview-section {
  padding: var(--spacing-xl);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.preview-section h3 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.preview-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm) 0;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.preview-item:last-child {
  border-bottom: none;
}

.preview-label {
  color: var(--color-text-muted);
  font-size: var(--font-size-sm);
}

.preview-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.preview-badges {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-sm);
}

.preview-badge {
  padding: var(--spacing-xs) 10px;
  background: var(--color-info-bg);
  color: var(--color-primary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.validation-section {
  padding: var(--spacing-xl);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
}

.validation-section h3 {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.validation-errors {
  display: flex;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
}

.error-icon {
  width: 24px;
  height: 24px;
  color: var(--color-error);
  flex-shrink: 0;
}

.validation-errors h4 {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-error);
  margin: 0 0 var(--spacing-sm) 0;
}

.validation-errors ul {
  margin: 0;
  padding-left: var(--spacing-xl);
  color: var(--color-error);
}

.validation-errors li {
  margin-bottom: var(--spacing-xs);
}

.validation-success {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-success-bg);
  border: var(--border-width-thin) solid var(--color-success);
  border-radius: var(--border-radius-md);
  color: var(--color-success);
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
  margin-top: var(--spacing-xl);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.spacer {
  flex: 1;
}

.btn-primary {
  display: flex;
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
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover:not(:disabled) {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
}

.btn-secondary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}
</style>

