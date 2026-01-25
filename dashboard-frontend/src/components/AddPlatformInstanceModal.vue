<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Shield class="modal-title-icon" />
              <h2>{{ editing ? 'Edit Platform Instance' : 'Add Platform Instance' }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="handleSubmit" class="instance-form">
              <div class="form-group">
                <label>Name *</label>
                <input
                  v-model="form.name"
                  type="text"
                  required
                  placeholder="e.g., Production Salesforce Org"
                />
              </div>

              <div class="form-group">
                <label>Platform Type *</label>
                <Dropdown
                  v-model="form.type"
                  :options="typeOptions"
                  placeholder="Select platform type..."
                  @update:modelValue="handleTypeChange"
                />
              </div>

              <div class="form-group">
                <label>Environment *</label>
                <Dropdown
                  v-model="form.environment"
                  :options="environmentOptions"
                  placeholder="Select environment..."
                />
              </div>

              <div class="form-group">
                <label>Baseline *</label>
                <Dropdown
                  v-model="form.baselineId"
                  :options="filteredBaselineOptions"
                  placeholder="Select baseline..."
                  :disabled="!form.type || !form.environment"
                />
                <small v-if="!form.type || !form.environment">
                  Select platform type and environment first
                </small>
              </div>

              <div class="form-group">
                <label>Description</label>
                <textarea
                  v-model="form.description"
                  rows="3"
                  placeholder="Describe this platform instance..."
                ></textarea>
              </div>

              <div class="form-group">
                <label>Connection Configuration (JSON) *</label>
                <textarea
                  v-model="form.configJson"
                  rows="6"
                  required
                  placeholder='{"apiKey": "your-key", "endpoint": "https://api.example.com"}'
                  class="json-input"
                ></textarea>
                <small>Connection settings as JSON</small>
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="!isFormValid">
                  {{ editing ? 'Update' : 'Add' }} Instance
                </button>
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
import { Shield, X } from 'lucide-vue-next';
import { Teleport } from 'vue';
import Dropdown from './Dropdown.vue';

const props = defineProps<{
  show: boolean;
  instance: any | null;
  baselines: any[];
}>();

const emit = defineEmits<{
  close: [];
  submit: [data: any];
}>();

const editing = computed(() => !!props.instance);

const form = ref({
  name: '',
  type: '',
  environment: '',
  baselineId: '',
  description: '',
  configJson: '{}',
});

const typeOptions = [
  { label: 'Salesforce', value: 'salesforce' },
  { label: 'Elastic Cloud', value: 'elastic-cloud' },
  { label: 'IDP / Kubernetes', value: 'idp-kubernetes' },
  { label: 'ServiceNow', value: 'servicenow' },
  { label: 'AWS', value: 'aws' },
  { label: 'Azure', value: 'azure' },
  { label: 'Other', value: 'other' },
];

const environmentOptions = [
  { label: 'Production', value: 'production' },
  { label: 'Staging', value: 'staging' },
  { label: 'Development', value: 'development' },
];

const getPlatformFromType = (type: string): string => {
  const mapping: Record<string, string> = {
    'salesforce': 'salesforce',
    'elastic-cloud': 'elastic',
    'idp-kubernetes': 'idp-kubernetes',
    'servicenow': 'servicenow',
  };
  return mapping[type] || '';
};

const filteredBaselineOptions = computed(() => {
  if (!form.value.type || !form.value.environment) {
    return [];
  }
  
  const platform = getPlatformFromType(form.value.type);
  if (!platform) {
    return [];
  }
  
  return props.baselines
    .filter(b => b.platform === platform && b.environment === form.value.environment)
    .map(b => ({
      label: b.name,
      value: b.id,
    }));
});

const handleTypeChange = () => {
  // Reset baseline when type changes
  form.value.baselineId = '';
};

watch(() => props.instance, (val) => {
  if (val) {
    form.value = {
      name: val.name,
      type: val.type,
      environment: val.environment || '',
      baselineId: val.baselineId || '',
      description: val.description || '',
      configJson: val.connectionConfig ? JSON.stringify(val.connectionConfig, null, 2) : '{}',
    };
  } else {
    form.value = {
      name: '',
      type: '',
      environment: '',
      baselineId: '',
      description: '',
      configJson: '{}',
    };
  }
}, { immediate: true });

const isFormValid = computed(() => {
  return form.value.name && 
         form.value.type && 
         form.value.environment &&
         form.value.baselineId &&
         form.value.configJson.trim();
});

const handleSubmit = () => {
  let config = {};
  try {
    config = JSON.parse(form.value.configJson);
  } catch (e) {
    alert('Invalid JSON in configuration field');
    return;
  }

  emit('submit', {
    name: form.value.name,
    type: form.value.type,
    environment: form.value.environment,
    baselineId: form.value.baselineId,
    description: form.value.description || undefined,
    connectionConfig: config,
  });
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--color-bg-primary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 90%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.modal-header h2 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.modal-close {
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-xs);
  border-radius: var(--border-radius-md);
  transition: var(--transition-all);
}

.modal-close:hover {
  background: var(--color-info-bg);
  color: var(--color-text-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-xl);
}

.instance-form {
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
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  font-family: inherit;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.json-input {
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
}

.form-group small {
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-md);
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-primary,
.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-xl);
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
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
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-text-secondary);
}

.btn-secondary:hover {
  background: var(--color-info-bg);
  border-color: var(--border-color-primary-active);
  color: var(--color-text-primary);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
