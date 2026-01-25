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
              :class="{ 'duplicate-type': isDuplicateDomain(harness) }"
            >
              <label class="checkbox-label">
                <input 
                  type="checkbox"
                  :value="harness.id"
                  v-model="form.harnessIds"
                    :disabled="isDuplicateDomain(harness)"
                />
                <div class="harness-info">
                  <span class="harness-name">{{ harness.name }}</span>
                  <span v-if="harness.description" class="harness-description">
                    {{ harness.description }}
                  </span>
                  <span class="harness-meta">
                    {{ harness.testSuiteIds?.length || 0 }} suites
                    <span v-if="harness.team"> • {{ harness.team }}</span>
                    <span v-if="harness.domain" class="harness-type-badge"> • Domain: {{ harness.domain }}</span>
                  </span>
                  <span v-if="isDuplicateDomain(harness)" class="duplicate-warning">
                    ⚠️ Another harness with domain "{{ harness.domain }}" is already selected
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
import type { BatteryExecutionConfig } from '../../heimdall-framework/core/types';

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
  const domainCounts = new Map<string, number>();
  form.value.harnessIds.forEach(harnessId => {
    const harness = availableHarnesses.value.find(h => h.id === harnessId);
    if (harness && harness.domain) {
      domainCounts.set(harness.domain, (domainCounts.get(harness.domain) || 0) + 1);
    }
  });
  return Array.from(domainCounts.values()).some(count => count > 1);
});

const isDuplicateDomain = (harness: any) => {
  if (!harness.domain || !form.value.harnessIds.includes(harness.id)) {
    return false;
  }
  const selectedCount = form.value.harnessIds.filter(id => {
    const h = availableHarnesses.value.find(har => har.id === id);
    return h && h.domain === harness.domain;
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

    const response = await axios.post('/api/v1/test-batteries', payload);
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
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.page-description {
  color: var(--color-text-secondary);
  opacity: 0.7;
  margin: 0;
}

.header-actions {
  display: flex;
  gap: var(--spacing-md);
}

.action-btn {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-md) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
}

.save-btn {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.save-btn:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: var(--shadow-primary-hover);
}

.save-btn:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.cancel-btn {
  background: var(--border-color-muted);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.cancel-btn:hover {
  background: var(--border-color-primary);
  opacity: 0.2;
}

.action-icon {
  width: 16px;
  height: 16px;
}

.form-container {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
}

.battery-form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.form-section {
  padding: var(--spacing-xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
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
  margin: 0 0 var(--spacing-lg) 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  margin-bottom: var(--spacing-lg);
}

.form-group:last-child {
  margin-bottom: 0;
}

.form-group label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.form-input {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.form-input:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
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
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  opacity: 0.6;
  margin: 0;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
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
  gap: var(--spacing-md);
  max-height: 500px;
  overflow-y: auto;
  padding: var(--spacing-sm);
}

.harness-option {
  padding: var(--spacing-base);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  transition: var(--transition-all);
}

.harness-option:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--color-bg-overlay-dark);
}

.harness-info {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  flex: 1;
}

.harness-name {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.harness-description {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  opacity: 0.7;
}

.harness-meta {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  opacity: 0.5;
}

.harness-type-badge {
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
}

.duplicate-warning {
  display: block;
  margin-top: var(--spacing-xs);
  font-size: var(--font-size-xs);
  color: var(--color-error);
}

.harness-option.duplicate-type {
  border-color: var(--color-error);
  background: var(--color-error-bg);
}

.validation-warning {
  margin-top: var(--spacing-base);
  padding: var(--spacing-md);
  background: var(--color-warning-bg);
  border: var(--border-width-thin) solid var(--color-warning);
  border-radius: var(--border-radius-sm);
  color: var(--color-warning);
  font-size: var(--font-size-sm);
}

.loading,
.error,
.empty-state {
  padding: var(--spacing-base);
  text-align: center;
  color: var(--color-text-secondary);
  opacity: 0.7;
  font-size: var(--font-size-sm);
}

.error {
  color: var(--color-error);
}

.empty-state a {
  color: var(--color-primary);
  text-decoration: underline;
}
</style>

