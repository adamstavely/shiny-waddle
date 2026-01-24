<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Layers class="modal-title-icon" />
              <h2>{{ editingHarness ? 'Edit Test Harness' : 'Create Test Harness' }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body">
            <form @submit.prevent="save" class="harness-form">
              <div class="form-group">
                <label>Name *</label>
                <input 
                  v-model="form.name" 
                  type="text" 
                  required 
                  placeholder="Enter harness name"
                />
              </div>

              <div class="form-group">
                <label>Description *</label>
                <textarea 
                  v-model="form.description" 
                  rows="3"
                  required
                  placeholder="Enter harness description"
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
                <small>All test suites in this harness must have the same test type.</small>
              </div>

              <div class="form-section">
                <h3 class="section-title">Test Suites</h3>
                <div v-if="form.testType" class="type-filter-info">
                  <small>Showing only suites with type: <strong>{{ form.testType }}</strong></small>
                </div>
                <div v-if="loadingSuites" class="loading">Loading test suites...</div>
                <div v-else-if="suitesError" class="error">{{ suitesError }}</div>
                <div v-else-if="availableSuites.length === 0" class="empty-state">
                  <p>No test suites available. Create a test suite first.</p>
                </div>
                <div v-else class="selection-list">
                  <div
                    v-for="suite in filteredSuites"
                    :key="suite.id"
                    class="selection-option"
                    :class="{ 'type-mismatch': form.testType && suite.testType !== form.testType }"
                  >
                    <label class="checkbox-label">
                      <input 
                        type="checkbox"
                        :value="suite.id"
                        v-model="form.testSuiteIds"
                        :disabled="form.testType && suite.testType !== form.testType"
                      />
                      <div class="option-info">
                        <span class="option-name">{{ suite.name }}</span>
                        <span class="option-meta">
                          {{ suite.application }}
                          <span v-if="suite.team"> • {{ suite.team }}</span>
                          <span v-if="suite.testType" class="suite-type-badge"> • Type: {{ suite.testType }}</span>
                        </span>
                      </div>
                    </label>
                  </div>
                  <div v-if="form.testType && filteredSuites.length === 0" class="empty-state">
                    <p>No test suites found with type "{{ form.testType }}". Create a test suite with this type first.</p>
                  </div>
                </div>
              </div>

              <div class="form-section">
                <h3 class="section-title">Applications</h3>
                <div v-if="loadingApplications" class="loading">Loading applications...</div>
                <div v-else-if="applicationsError" class="error">{{ applicationsError }}</div>
                <div v-else-if="availableApplications.length === 0" class="empty-state">
                  <p>No applications available. Create an application first.</p>
                </div>
                <div v-else class="selection-list">
                  <div
                    v-for="app in availableApplications"
                    :key="app.id"
                    class="selection-option"
                  >
                    <label class="checkbox-label">
                      <input 
                        type="checkbox"
                        :value="app.id"
                        v-model="form.applicationIds"
                      />
                      <div class="option-info">
                        <span class="option-name">{{ app.name }}</span>
                        <span class="option-meta" v-if="app.team">
                          {{ app.team }}
                        </span>
                      </div>
                    </label>
                  </div>
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  <div v-if="saving" class="spinner-small"></div>
                  <span v-else>{{ editingHarness ? 'Update' : 'Create' }} Harness</span>
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
import { Layers, X } from 'lucide-vue-next';
import axios from 'axios';
import type { TestHarness } from '../../../core/types';

interface Props {
  show: boolean;
  editingHarness?: TestHarness | null;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  close: [];
  saved: [harness: TestHarness];
}>();

const form = ref({
  name: '',
  description: '',
  team: '',
  testType: '' as string,
  testSuiteIds: [] as string[],
  applicationIds: [] as string[],
});

const availableSuites = ref<any[]>([]);
const loadingSuites = ref(false);
const suitesError = ref<string | null>(null);

const filteredSuites = computed(() => {
  if (!form.value.testType) {
    return availableSuites.value;
  }
  return availableSuites.value.filter(suite => suite.testType === form.value.testType);
});

const availableApplications = ref<any[]>([]);
const loadingApplications = ref(false);
const applicationsError = ref<string | null>(null);

const saving = ref(false);

const loadSuites = async () => {
  loadingSuites.value = true;
  suitesError.value = null;
  try {
    const response = await axios.get('/api/v1/test-suites');
    availableSuites.value = response.data || [];
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to load test suites';
    console.error('Error loading suites:', err);
  } finally {
    loadingSuites.value = false;
  }
};

const loadApplications = async () => {
  loadingApplications.value = true;
  applicationsError.value = null;
  try {
    const response = await axios.get("/api/v1/applications");
    availableApplications.value = response.data || [];
  } catch (err: any) {
    applicationsError.value = err.response?.data?.message || 'Failed to load applications';
    console.error('Error loading applications:', err);
  } finally {
    loadingApplications.value = false;
  }
};

const resetForm = () => {
  form.value = {
    name: '',
    description: '',
    team: '',
    testType: '',
    testSuiteIds: [],
    applicationIds: [],
  };
};

const populateForm = (harness: TestHarness) => {
  form.value = {
    name: harness.name,
    description: harness.description,
    team: harness.team || '',
    testType: (harness as any).testType || '',
    testSuiteIds: harness.testSuiteIds || [],
    applicationIds: harness.applicationIds || [],
  };
};

const save = async () => {
  if (!form.value.testType) {
    alert('Please select a test type');
    saving.value = false;
    return;
  }

  saving.value = true;
  try {
    const payload: any = {
      name: form.value.name,
      description: form.value.description,
      team: form.value.team || undefined,
      testType: form.value.testType,
      testSuiteIds: form.value.testSuiteIds,
      applicationIds: form.value.applicationIds,
    };

    let response;
    if (props.editingHarness) {
      response = await axios.put(`/api/v1/test-harnesses/${props.editingHarness.id}`, payload);
    } else {
      response = await axios.post('/api/v1/test-harnesses', payload);
    }

    emit('saved', response.data);
    resetForm();
    close();
  } catch (err: any) {
    console.error('Error saving harness:', err);
    alert(err.response?.data?.message || 'Failed to save test harness');
  } finally {
    saving.value = false;
  }
};

const close = () => {
  resetForm();
  emit('close');
};

// Watch for editing harness changes
watch(() => props.editingHarness, (harness) => {
  if (harness) {
    populateForm(harness);
  } else {
    resetForm();
  }
}, { immediate: true });

// Watch for show changes to load data
watch(() => props.show, (isShowing) => {
  if (isShowing) {
    loadSuites();
    loadApplications();
    if (props.editingHarness) {
      populateForm(props.editingHarness);
    } else {
      resetForm();
    }
  }
}, { immediate: true });

onMounted(() => {
  if (props.show) {
    loadSuites();
    loadApplications();
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

.harness-form {
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

.form-select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234facfe' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  padding-right: 40px;
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

.form-section {
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.3);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.type-filter-info {
  margin-bottom: 1rem;
  padding: 0.5rem;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.75rem;
}

.type-filter-info strong {
  text-transform: capitalize;
}

.suite-type-badge {
  color: #4facfe;
  font-weight: 500;
}

.selection-option.type-mismatch {
  opacity: 0.5;
  background: rgba(15, 20, 25, 0.2);
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

.selection-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  max-height: 300px;
  overflow-y: auto;
}

.selection-option {
  padding: 1rem;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  transition: all 0.2s;
}

.selection-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.6);
}

.option-info {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  flex: 1;
}

.option-name {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.option-meta {
  font-size: 0.75rem;
  color: #718096;
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

