<template>
  <div class="policy-builder-wizard">
    <!-- Progress Indicator -->
    <div class="wizard-progress">
      <div
        v-for="(step, index) in steps"
        :key="index"
        class="progress-step"
        :class="{ active: currentStep === index + 1, completed: currentStep > index + 1 }"
      >
        <div class="step-number">{{ index + 1 }}</div>
        <div class="step-label">{{ step.label }}</div>
      </div>
    </div>

    <!-- Step Content -->
    <div class="wizard-content">
      <!-- Step 1: Policy Type Selection -->
      <div v-if="currentStep === 1" class="wizard-step">
        <h3>Select Policy Type</h3>
        <div class="policy-type-selector">
          <button
            @click="selectPolicyType('rbac')"
            class="policy-type-card"
            :class="{ active: formData.rules !== undefined }"
          >
            <h4>RBAC</h4>
            <p>Role-Based Access Control</p>
            <p class="description">Control access based on user roles</p>
          </button>
          <button
            @click="selectPolicyType('abac')"
            class="policy-type-card"
            :class="{ active: formData.conditions !== undefined }"
          >
            <h4>ABAC</h4>
            <p>Attribute-Based Access Control</p>
            <p class="description">Control access based on attributes</p>
          </button>
        </div>

        <!-- Template Selector -->
        <div v-if="selectedPolicyType" class="template-selector">
          <h4>Or start from a template:</h4>
          <select v-model="selectedTemplate" @change="applyTemplate">
            <option value="">Select a template...</option>
            <option
              v-for="template in templates"
              :key="template.id"
              :value="template.id"
            >
              {{ template.name }}
            </option>
          </select>
        </div>
      </div>

      <!-- Step 2: Basic Information -->
      <div v-if="currentStep === 2" class="wizard-step">
        <h3>Basic Information</h3>
        <div class="form-group">
          <label>Policy Name *</label>
          <input v-model="formData.name" type="text" required />
          <span v-if="getFieldErrors('name').length" class="error">
            {{ getFieldErrors('name')[0].message }}
          </span>
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea v-model="formData.description" rows="3"></textarea>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Version *</label>
            <input v-model="formData.version" type="text" required />
          </div>
          <div class="form-group">
            <label>Status</label>
            <select v-model="formData.status">
              <option value="draft">Draft</option>
              <option value="active">Active</option>
              <option value="deprecated">Deprecated</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label>Effect</label>
          <div class="radio-group">
            <label>
              <input type="radio" v-model="formData.effect" value="allow" />
              Allow
            </label>
            <label>
              <input type="radio" v-model="formData.effect" value="deny" />
              Deny
            </label>
          </div>
        </div>
      </div>

      <!-- Step 3: Policy Definition (RBAC) -->
      <div v-if="currentStep === 3 && formData.rules !== undefined" class="wizard-step">
        <h3>Define Rules</h3>
        <div v-for="(rule, index) in formData.rules" :key="rule.id" class="rule-item">
          <h4>Rule {{ index + 1 }}</h4>
          <div class="form-group">
            <label>Role *</label>
            <input v-model="rule.role" type="text" required />
          </div>
          <div class="form-group">
            <label>Resource Sensitivity</label>
            <select v-model="rule.resourceSensitivity" multiple>
              <option value="public">Public</option>
              <option value="internal">Internal</option>
              <option value="confidential">Confidential</option>
              <option value="restricted">Restricted</option>
            </select>
          </div>
          <button @click="removeRule(index)" class="btn-danger">Remove Rule</button>
        </div>
        <button @click="addRule" class="btn-secondary">Add Rule</button>
      </div>

      <!-- Step 3: Policy Definition (ABAC) -->
      <div v-if="currentStep === 3 && formData.conditions !== undefined" class="wizard-step">
        <h3>Define Conditions</h3>
        <div class="form-group">
          <label>Priority</label>
          <input v-model.number="formData.priority" type="number" min="0" />
        </div>
        <div v-for="(condition, index) in formData.conditions" :key="condition.id" class="condition-item">
          <h4>Condition {{ index + 1 }}</h4>
          <div class="form-row">
            <div class="form-group">
              <label>Attribute *</label>
              <input v-model="condition.attribute" type="text" placeholder="subject.department" required />
            </div>
            <div class="form-group">
              <label>Operator *</label>
              <select v-model="condition.operator">
                <option value="equals">Equals</option>
                <option value="notEquals">Not Equals</option>
                <option value="in">In</option>
                <option value="notIn">Not In</option>
                <option value="contains">Contains</option>
                <option value="greaterThan">Greater Than</option>
                <option value="lessThan">Less Than</option>
              </select>
            </div>
          </div>
          <div class="form-group">
            <label>Value *</label>
            <input v-model="condition.value" type="text" required />
          </div>
          <button @click="removeCondition(index)" class="btn-danger">Remove Condition</button>
        </div>
        <button @click="addCondition" class="btn-secondary">Add Condition</button>
      </div>

      <!-- Step 4: Review -->
      <div v-if="currentStep === 4" class="wizard-step">
        <h3>Review Policy</h3>
        <div class="review-section">
          <h4>Policy Details</h4>
          <pre>{{ JSON.stringify(formData, null, 2) }}</pre>
        </div>
        <div class="review-section">
          <h4>JSON Preview</h4>
          <pre>{{ jsonPreview }}</pre>
        </div>
      </div>
    </div>

    <!-- Navigation Buttons -->
    <div class="wizard-actions">
      <button v-if="currentStep > 1" @click="previousStep" class="btn-secondary">
        Previous
      </button>
      <button v-if="currentStep < totalSteps" @click="nextStep" class="btn-primary">
        Next
      </button>
      <button v-if="currentStep === totalSteps" @click="savePolicy" class="btn-primary">
        Save Policy
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
// Simple UUID generator (fallback if uuid package not available)
const generateUUID = () => {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
};
import { policyBuilderService } from '../../services/policy-builder.service';
import { usePolicySync } from '../../composables/usePolicySync';
import { usePolicyValidation } from '../../composables/usePolicyValidation';
import type { PolicyFormData, RBACRuleFormData, ABACConditionFormData, PolicyTemplate } from '../../types/policy-builder';

const props = defineProps<{
  policyId?: string;
}>();

const emit = defineEmits<{
  saved: [policyId: string];
  cancelled: [];
}>();

const { syncToJson } = usePolicySync();
const { validate, getFieldErrors } = usePolicyValidation();

const currentStep = ref(1);
const totalSteps = 4;
const selectedPolicyType = ref<'rbac' | 'abac' | null>(null);
const selectedTemplate = ref('');
const templates = ref<PolicyTemplate[]>([]);
const jsonPreview = ref('');

const formData = ref<PolicyFormData>({
  name: '',
  description: '',
  version: '1.0.0',
  status: 'draft',
  effect: 'allow',
});

const steps = [
  { label: 'Policy Type' },
  { label: 'Basic Info' },
  { label: 'Definition' },
  { label: 'Review' },
];

const selectPolicyType = (type: 'rbac' | 'abac') => {
  selectedPolicyType.value = type;
  if (type === 'rbac') {
    formData.value.rules = [];
    delete formData.value.conditions;
    delete formData.value.priority;
  } else {
    formData.value.conditions = [];
    formData.value.priority = 100;
    delete formData.value.rules;
  }
};

const addRule = () => {
  if (!formData.value.rules) formData.value.rules = [];
  formData.value.rules.push({
    id: generateUUID(),
    effect: 'allow',
    role: '',
  });
};

const removeRule = (index: number) => {
  if (formData.value.rules) {
    formData.value.rules.splice(index, 1);
  }
};

const addCondition = () => {
  if (!formData.value.conditions) formData.value.conditions = [];
  formData.value.conditions.push({
    id: generateUUID(),
    attribute: '',
    operator: 'equals',
    value: '',
  });
};

const removeCondition = (index: number) => {
  if (formData.value.conditions) {
    formData.value.conditions.splice(index, 1);
  }
};

const applyTemplate = async () => {
  if (!selectedTemplate.value) return;
  try {
    const template = await policyBuilderService.getTemplate(selectedTemplate.value);
    formData.value = { ...template.template };
    selectedPolicyType.value = template.policyType;
    jsonPreview.value = template.exampleJson;
  } catch (error) {
    console.error('Failed to apply template:', error);
  }
};

const nextStep = async () => {
  // Validate current step
  if (currentStep.value === 1 && !selectedPolicyType.value) {
    alert('Please select a policy type');
    return;
  }

  if (currentStep.value === 2) {
    const result = await validate(formData.value);
    if (!result.valid) {
      alert('Please fix validation errors');
      return;
    }
  }

  if (currentStep.value === 3) {
    // Update JSON preview
    try {
      const result = await syncToJson(formData.value);
      jsonPreview.value = result;
    } catch (error) {
      console.error('Failed to sync to JSON:', error);
    }
  }

  if (currentStep.value < totalSteps) {
    currentStep.value++;
  }
};

const previousStep = () => {
  if (currentStep.value > 1) {
    currentStep.value--;
  }
};

const savePolicy = async () => {
  try {
    // Create builder state and save policy
    const state = await policyBuilderService.createBuilderState(
      selectedPolicyType.value!,
      props.policyId
    );
    
    // Update state with form data
    await policyBuilderService.updateBuilderState(state.id, {
      formData: formData.value,
      jsonData: jsonPreview.value,
    });

    // Create or update policy
    let policyId: string;
    if (props.policyId) {
      const policy = await policyBuilderService.updatePolicyFromBuilder(props.policyId, state.id);
      policyId = policy.id;
    } else {
      const policy = await policyBuilderService.createPolicyFromBuilder(state.id);
      policyId = policy.id;
    }

    emit('saved', policyId);
  } catch (error) {
    console.error('Failed to save policy:', error);
    alert('Failed to save policy. Please try again.');
  }
};

onMounted(async () => {
  // Load templates
  try {
    templates.value = await policyBuilderService.getTemplates();
  } catch (error) {
    console.error('Failed to load templates:', error);
  }

  // If editing, load existing policy
  if (props.policyId) {
    // TODO: Load existing policy and populate form
  }
});
</script>

<style scoped>
.policy-builder-wizard {
  max-width: 800px;
  margin: 0 auto;
}

.wizard-progress {
  display: flex;
  justify-content: space-between;
  margin-bottom: 2rem;
}

.progress-step {
  flex: 1;
  text-align: center;
  position: relative;
}

.step-number {
  width: 40px;
  height: 40px;
  border-radius: 50%;
  background: #e0e0e0;
  display: flex;
  align-items: center;
  justify-content: center;
  margin: 0 auto 0.5rem;
}

.progress-step.active .step-number {
  background: #4299e1;
  color: white;
}

.progress-step.completed .step-number {
  background: #48bb78;
  color: white;
}

.wizard-content {
  min-height: 400px;
  padding: 2rem;
  background: white;
  border-radius: 8px;
  margin-bottom: 2rem;
}

.policy-type-selector {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
  margin: 2rem 0;
}

.policy-type-card {
  padding: 2rem;
  border: 2px solid #e0e0e0;
  border-radius: 8px;
  cursor: pointer;
  text-align: center;
  transition: all 0.2s;
}

.policy-type-card:hover {
  border-color: #4299e1;
}

.policy-type-card.active {
  border-color: #4299e1;
  background: #ebf8ff;
}

.form-group {
  margin-bottom: 1.5rem;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.error {
  color: #f56565;
  font-size: 0.875rem;
  margin-top: 0.25rem;
  display: block;
}

.wizard-actions {
  display: flex;
  justify-content: space-between;
  gap: 1rem;
}
</style>
