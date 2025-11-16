<template>
  <div class="test-battery-create-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div class="header-left">
          <h1 class="page-title">Create Test Battery</h1>
          <p class="page-description">Collections of test harnesses that can be executed together</p>
        </div>
        <div class="header-actions">
          <button @click="save" class="action-btn save-btn" :disabled="saving">
            <Save class="action-icon" />
            {{ saving ? 'Saving...' : 'Create Battery' }}
          </button>
          <button @click="goBack" class="action-btn cancel-btn">
            <ArrowLeft class="action-icon" />
            Cancel
          </button>
        </div>
      </div>
    </div>

    <div class="form-container">
      <form @submit.prevent="save" class="battery-form">
        <!-- Basic Information and Execution Config Side by Side -->
        <div class="form-section form-section-half">
          <h3 class="section-title">Basic Information</h3>
          <div class="form-group">
            <label>Name *</label>
            <input 
              v-model="form.name" 
              type="text" 
              required 
              placeholder="Enter battery name"
              class="form-input"
            />
          </div>

          <div class="form-group">
            <label>Description</label>
            <textarea 
              v-model="form.description" 
              rows="3"
              placeholder="Enter battery description (optional)"
              class="form-input"
            ></textarea>
          </div>

          <div class="form-group">
            <label>Team</label>
            <input 
              v-model="form.team" 
              type="text" 
              placeholder="Enter team name (optional)"
              class="form-input"
            />
          </div>
        </div>

        <div class="form-section form-section-half">
          <h3 class="section-title">Execution Configuration</h3>
          
          <div class="form-group">
            <label>Execution Mode</label>
            <select v-model="form.executionConfig.executionMode" class="form-input form-select">
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
              class="form-input"
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

        <div class="form-section form-section-full">
          <h3 class="section-title">Test Harnesses</h3>
          <div v-if="loadingHarnesses" class="loading">Loading harnesses...</div>
          <div v-else-if="harnessesError" class="error">{{ harnessesError }}</div>
          <div v-else-if="availableHarnesses.length === 0" class="empty-state">
            <p>No test harnesses available. <router-link to="/tests/harnesses/new">Create a test harness first</router-link>.</p>
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
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Battery, Save, ArrowLeft } from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import type { BatteryExecutionConfig } from '../../../core/types';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Batteries', to: '/tests/batteries' },
  { label: 'Create Test Battery' },
];

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
    const response = await axios.get('/api/test-harnesses');
    availableHarnesses.value = response.data || [];
  } catch (err: any) {
    harnessesError.value = err.response?.data?.message || 'Failed to load test harnesses';
    console.error('Error loading harnesses:', err);
  } finally {
    loadingHarnesses.value = false;
  }
};

const save = async () => {
  if (hasDuplicateTypes.value) {
    alert('All harnesses in a battery must have different types. Please remove duplicate types.');
    return;
  }

  if (!form.value.name) {
    alert('Please enter a battery name');
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

    const response = await axios.post('/api/test-batteries', payload);
    await router.push({ path: `/tests/batteries/${response.data.id || response.data._id}` });
  } catch (err: any) {
    console.error('Error saving battery:', err);
    alert(err.response?.data?.message || 'Failed to save test battery');
  } finally {
    saving.value = false;
  }
};

const goBack = () => {
  router.push('/tests/batteries');
};

onMounted(() => {
  loadHarnesses();
});
</script>

<style scoped>
.test-battery-create-page {
  padding: 2rem;
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.header-left {
  flex: 1;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: rgba(255, 255, 255, 0.7);
  margin: 0;
}

.header-actions {
  display: flex;
  gap: 0.75rem;
}

.action-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.save-btn {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.save-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.save-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.cancel-btn {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.cancel-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.form-container {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 2rem;
}

.battery-form {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.form-section {
  padding: 2rem;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.form-section-full {
  width: 100%;
}

.form-section-half {
  width: 100%;
}

@media (min-width: 1400px) {
  .battery-form {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
  }
  
  .form-section-full {
    grid-column: 1 / -1;
  }
  
  .form-section-half {
    width: auto;
  }
}

.section-title {
  margin: 0 0 1.5rem 0;
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1.5rem;
}

.form-group:last-child {
  margin-bottom: 0;
}

.form-group label {
  font-weight: 500;
  color: #ffffff;
  font-size: 0.875rem;
}

.form-input {
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
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

.form-input textarea {
  resize: vertical;
  min-height: 80px;
}

.form-select {
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%234facfe' d='M6 9L1 4h10z'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 12px center;
  padding-right: 40px;
}

.field-help {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
  margin: 0;
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
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 1rem;
  max-height: 500px;
  overflow-y: auto;
  padding: 0.5rem;
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
  color: rgba(255, 255, 255, 0.7);
}

.harness-meta {
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.5);
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
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.875rem;
}

.error {
  color: #fc8181;
}

.empty-state a {
  color: #4facfe;
  text-decoration: underline;
}
</style>

