<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Battery class="modal-title-icon" />
              <h2>{{ editingBattery ? 'Edit Test Battery' : 'Create Test Battery' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <form @submit.prevent="save" class="battery-form">
              <div class="form-group">
                <label>Name *</label>
                <input 
                  v-model="form.name" 
                  type="text" 
                  required 
                  placeholder="Enter battery name"
                />
              </div>

              <div class="form-group">
                <label>Description</label>
                <textarea 
                  v-model="form.description" 
                  rows="3"
                  placeholder="Enter battery description (optional)"
                ></textarea>
              </div>

              <div class="form-group">
                <label>Team</label>
                <input 
                  v-model="form.team" 
                  type="text" 
                  placeholder="Enter team name (optional)"
                />
              </div>

              <div class="form-section">
                <h3 class="section-title">Execution Configuration</h3>
                
                <div class="form-group">
                  <label>Execution Mode</label>
                  <select v-model="form.executionConfig.executionMode">
                    <option value="sequential">Sequential</option>
                    <option value="parallel">Parallel</option>
                  </select>
                  <p class="field-help">
                    Sequential: Run harnesses one after another. Parallel: Run all harnesses simultaneously.
                  </p>
                </div>

                <div class="form-group">
                  <label>Timeout (seconds)</label>
                  <input 
                    v-model.number="form.executionConfig.timeout" 
                    type="number" 
                    min="0"
                    placeholder="Optional timeout in seconds"
                  />
                  <p class="field-help">
                    Maximum time to wait for battery execution. Leave empty for no timeout.
                  </p>
                </div>

                <div class="form-group">
                  <label class="checkbox-label">
                    <input 
                      v-model="form.executionConfig.stopOnFailure" 
                      type="checkbox" 
                    />
                    Stop on Failure
                  </label>
                  <p class="field-help">
                    If enabled, battery execution will stop if any harness fails (sequential mode only).
                  </p>
                </div>
              </div>

              <div class="form-section">
                <h3 class="section-title">Test Harnesses</h3>
                <div v-if="loadingHarnesses" class="loading">Loading harnesses...</div>
                <div v-else-if="harnessesError" class="error">{{ harnessesError }}</div>
                <div v-else-if="availableHarnesses.length === 0" class="empty-state">
                  <p>No test harnesses available. Create a test harness first.</p>
                </div>
                <div v-else class="harnesses-selection">
                  <div
                    v-for="harness in availableHarnesses"
                    :key="harness.id"
                    class="harness-option"
                    :class="{ 'duplicate-type': isDuplicateType(harness) }"
                  >
                    <label class="checkbox-label">
                      <input 
                        type="checkbox"
                        :value="harness.id"
                        v-model="form.harnessIds"
                        :disabled="isDuplicateType(harness)"
                      />
                      <div class="harness-info">
                        <span class="harness-name">{{ harness.name }}</span>
                        <span v-if="harness.description" class="harness-description">
                          {{ harness.description }}
                        </span>
                        <span class="harness-meta">
                          {{ harness.testSuiteIds?.length || 0 }} suites
                          <span v-if="harness.team"> • {{ harness.team }}</span>
                          <span v-if="harness.testType" class="harness-type-badge"> • Type: {{ harness.testType }}</span>
                        </span>
                        <span v-if="isDuplicateType(harness)" class="duplicate-warning">
                          ⚠️ Another harness with type "{{ harness.testType }}" is already selected
                        </span>
                      </div>
                    </label>
                  </div>
                </div>
                <div v-if="hasDuplicateTypes" class="validation-warning">
                  <strong>⚠️ Warning:</strong> All harnesses in a battery must have different types. 
                  Please remove duplicate types.
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  <div v-if="saving" class="spinner-small"></div>
                  <span v-else>{{ editingBattery ? 'Update' : 'Create' }} Battery</span>
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
import { ref, computed, watch, onMounted } from 'vue';
import { Teleport } from 'vue';
import { Battery, X } from 'lucide-vue-next';
import axios from 'axios';
import type { TestBattery, BatteryExecutionConfig } from '../../../core/types';

interface Props {
  show: boolean;
  editingBattery?: TestBattery | null;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  close: [];
  saved: [battery: TestBattery];
}>();

const form = ref({
  name: '',
  description: '',
  team: '',
  harnessIds: [] as string[],
  executionConfig: {
    executionMode: 'sequential' as 'parallel' | 'sequential',
    timeout: undefined as number | undefined,
    stopOnFailure: false,
  } as BatteryExecutionConfig,
});

const availableHarnesses = ref<any[]>([]);
const loadingHarnesses = ref(false);
const harnessesError = ref<string | null>(null);
const saving = ref(false);

const selectedHarnessTypes = computed(() => {
  const types = new Set<string>();
  form.value.harnessIds.forEach(harnessId => {
    const harness = availableHarnesses.value.find(h => h.id === harnessId);
    if (harness && harness.testType) {
      types.add(harness.testType);
    }
  });
  return types;
});

const hasDuplicateTypes = computed(() => {
  const typeCounts = new Map<string, number>();
  form.value.harnessIds.forEach(harnessId => {
    const harness = availableHarnesses.value.find(h => h.id === harnessId);
    if (harness && harness.testType) {
      typeCounts.set(harness.testType, (typeCounts.get(harness.testType) || 0) + 1);
    }
  });
  return Array.from(typeCounts.values()).some(count => count > 1);
});

const isDuplicateType = (harness: any) => {
  if (!harness.testType || !form.value.harnessIds.includes(harness.id)) {
    return false;
  }
  const selectedCount = form.value.harnessIds.filter(id => {
    const h = availableHarnesses.value.find(har => har.id === id);
    return h && h.testType === harness.testType;
  }).length;
  return selectedCount > 1;
};

const loadHarnesses = async () => {
  loadingHarnesses.value = true;
  harnessesError.value = null;
  try {
    const response = await axios.get('/api/v1/test-harnesses');
    availableHarnesses.value = response.data || [];
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load test harnesses';
    console.error('Error loading harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const resetForm = () => {
  form.value = {
    name: '',
    description: '',
    team: '',
    harnessIds: [],
    executionConfig: {
      executionMode: 'sequential',
      timeout: undefined,
      stopOnFailure: false,
    },
  };
};

const populateForm = (battery: TestBattery) => {
  form.value = {
    name: battery.name,
    description: battery.description || '',
    team: battery.team || '',
    harnessIds: battery.harnessIds || [],
    executionConfig: {
      executionMode: battery.executionConfig?.executionMode || 'sequential',
      timeout: battery.executionConfig?.timeout,
      stopOnFailure: battery.executionConfig?.stopOnFailure || false,
    },
  };
};

const save = async () => {
  if (hasDuplicateTypes.value) {
    alert('All harnesses in a battery must have different types. Please remove duplicate types.');
    saving.value = false;
    return;
  }

  saving.value = true;
  try {
    const payload: any = {
      name: form.value.name,
      description: form.value.description || undefined,
      team: form.value.team || undefined,
      harnessIds: form.value.harnessIds,
      executionConfig: {
        executionMode: form.value.executionConfig.executionMode,
        timeout: form.value.executionConfig.timeout || undefined,
        stopOnFailure: form.value.executionConfig.stopOnFailure,
      },
    };

    let response;
    if (props.editingBattery) {
      response = await axios.put(`/api/v1/test-batteries/${props.editingBattery.id}`, payload);
    } else {
      response = await axios.post('/api/v1/test-batteries', payload);
    }

    emit('saved', response.data);
    resetForm();
    close();
  } catch (err: any) {
    console.error('Error saving battery:', err);
    alert(err.response?.data?.message || 'Failed to save test battery');
  } finally {
    saving.value = false;
  }
};

const close = () => {
  resetForm();
  emit('close');
};

// Watch for editing battery changes
watch(() => props.editingBattery, (battery) => {
  if (battery) {
    populateForm(battery);
  } else {
    resetForm();
  }
}, { immediate: true });

// Watch for show changes to load harnesses
watch(() => props.show, (isShowing) => {
  if (isShowing) {
    loadHarnesses();
    if (props.editingBattery) {
      populateForm(props.editingBattery);
    } else {
      resetForm();
    }
  }
}, { immediate: true });

onMounted(() => {
  if (props.show) {
    loadHarnesses();
  }
});
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
  padding: 2rem;
}

.modal-content {
  background: #1a1f2e;
  border-radius: 16px;
  width: 100%;
  max-width: 700px;
  max-height: 90vh;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 1.5rem 2rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  transition: all 0.2s;
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
  padding: 2rem;
  overflow-y: auto;
  flex: 1;
}

.battery-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.form-group input,
.form-group textarea,
.form-group select {
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group textarea:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.field-help {
  font-size: 0.75rem;
  color: #718096;
  margin: 0;
}

.form-section {
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.3);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.section-title {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
  font-weight: normal;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.harnesses-selection {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 300px;
  overflow-y: auto;
}

.harness-option {
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  transition: all 0.2s;
}

.harness-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.harness-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  flex: 1;
}

.harness-name {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.harness-description {
  font-size: 0.75rem;
  color: #a0aec0;
}

.harness-meta {
  font-size: 0.75rem;
  color: #718096;
}

.harness-type-badge {
  color: #4facfe;
  font-weight: 500;
}

.duplicate-warning {
  display: block;
  margin-top: 0.5rem;
  font-size: 0.75rem;
  color: #fc8181;
}

.harness-option.duplicate-type {
  border-color: rgba(252, 129, 129, 0.3);
  background: rgba(252, 129, 129, 0.05);
}

.validation-warning {
  margin-top: 1rem;
  padding: 0.75rem;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 6px;
  color: #fbbf24;
  font-size: 0.875rem;
}

.loading,
.error,
.empty-state {
  padding: 1rem;
  text-align: center;
  color: #a0aec0;
  font-size: 0.875rem;
}

.error {
  color: #fc8181;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-primary,
.btn-secondary {
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(15, 20, 25, 0.3);
  border-top-color: #0f1419;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
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

