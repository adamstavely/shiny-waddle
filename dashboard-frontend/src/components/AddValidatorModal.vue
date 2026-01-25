<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Plus class="modal-title-icon" />
              <h2>{{ editing ? 'Edit Validator' : 'Add Validator' }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <form @submit.prevent="handleSubmit" class="validator-form">
              <div class="form-group">
                <label>Validator ID *</label>
                <input
                  v-model="form.id"
                  type="text"
                  required
                  placeholder="e.g., access-control-validator"
                  :disabled="editing"
                />
                <small>Unique identifier (cannot be changed after creation)</small>
              </div>

              <div class="form-row">
                <div class="form-group">
                  <label>Name *</label>
                  <input
                    v-model="form.name"
                    type="text"
                    required
                    placeholder="e.g., Access Control Validator"
                  />
                </div>
                <div class="form-group">
                  <label>Version *</label>
                  <input
                    v-model="form.version"
                    type="text"
                    required
                    placeholder="e.g., 1.0.0"
                  />
                </div>
              </div>

              <div class="form-group">
                <label>Test Type *</label>
                <input
                  v-model="form.testType"
                  type="text"
                  required
                  placeholder="e.g., access-control"
                />
              </div>

              <div class="form-group">
                <label>Description *</label>
                <textarea
                  v-model="form.description"
                  rows="3"
                  required
                  placeholder="Describe what this validator does..."
                ></textarea>
              </div>

              <div class="form-group">
                <label>Configuration (JSON)</label>
                <textarea
                  v-model="form.configJson"
                  rows="6"
                  placeholder='{"apiKey": "your-key", "endpoint": "https://api.example.com"}'
                  class="json-input"
                ></textarea>
                <small>Validator configuration as JSON (optional)</small>
              </div>

              <div class="form-group">
                <label class="checkbox-label">
                  <input
                    v-model="form.enabled"
                    type="checkbox"
                    class="checkbox-input"
                  />
                  <span>Enable validator immediately</span>
                </label>
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="!isFormValid">
                  {{ editing ? 'Update' : 'Add' }} Validator
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
import { Plus, X } from 'lucide-vue-next';
import { Teleport } from 'vue';

interface Validator {
  id: string;
  name: string;
  description: string;
  testType: string;
  version: string;
  enabled: boolean;
  config?: Record<string, any>;
}

const props = defineProps<{
  show: boolean;
  validator: Validator | null;
}>();

const emit = defineEmits<{
  close: [];
  submit: [data: any];
}>();

const editing = computed(() => !!props.validator);

const form = ref({
  id: '',
  name: '',
  description: '',
  testType: '',
  version: '',
  configJson: '{}',
  enabled: true,
});

watch(() => props.validator, (val) => {
  if (val) {
    form.value = {
      id: val.id,
      name: val.name,
      description: val.description,
      testType: val.testType,
      version: val.version,
      configJson: val.config ? JSON.stringify(val.config, null, 2) : '{}',
      enabled: val.enabled,
    };
  } else {
    form.value = {
      id: '',
      name: '',
      description: '',
      testType: '',
      version: '',
      configJson: '{}',
      enabled: true,
    };
  }
}, { immediate: true });

const isFormValid = computed(() => {
  return form.value.id && form.value.name && form.value.description && form.value.testType && form.value.version;
});

const handleSubmit = () => {
  let config = {};
  try {
    if (form.value.configJson.trim()) {
      config = JSON.parse(form.value.configJson);
    }
  } catch (e) {
    alert('Invalid JSON in configuration field');
    return;
  }

  emit('submit', {
    ...form.value,
    config: Object.keys(config).length > 0 ? config : undefined,
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
  max-width: 700px;
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

.validator-form {
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

.form-group input:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.json-input {
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 10px;
  cursor: pointer;
  font-size: 0.9rem;
  color: #ffffff;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
  accent-color: #4facfe;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 12px;
  color: #0f1419;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

