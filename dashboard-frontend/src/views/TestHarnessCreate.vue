<template>
  <div class="test-harness-create-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div class="header-left">
          <h1 class="page-title">Create Test Harness</h1>
          <p class="page-description">Collections of test suites assigned to applications</p>
        </div>
        <div class="header-actions">
          <button @click="save" class="action-btn save-btn" :disabled="saving">
            <Save class="action-icon" />
            {{ saving ? 'Saving...' : 'Create Harness' }}
          </button>
          <button @click="goBack" class="action-btn cancel-btn">
            <ArrowLeft class="action-icon" />
            Cancel
          </button>
        </div>
      </div>
    </div>

    <div class="form-container">
      <form @submit.prevent="save" class="harness-form">
        <!-- Basic Information Section -->
        <div class="form-section form-section-full">
          <h3 class="section-title">Basic Information</h3>
          <div class="form-grid">
            <div class="form-group">
              <label>Name *</label>
              <input 
                v-model="form.name" 
                type="text" 
                required 
                placeholder="Enter harness name"
                class="form-input"
              />
            </div>

            <div class="form-group">
              <label>Domain *</label>
              <Dropdown
                v-model="form.domain"
                :options="domainOptions"
                placeholder="Select a domain..."
                required
                class="form-input"
              />
              <p class="field-help">All test suites in this harness must have the same domain.</p>
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

          <div class="form-group">
            <label>Description *</label>
            <textarea 
              v-model="form.description" 
              rows="3"
              required
              placeholder="Enter harness description"
              class="form-input"
            ></textarea>
          </div>
        </div>

        <!-- Test Suites Section -->
        <div class="form-section form-section-full">
          <h3 class="section-title">Test Suites</h3>
          <div v-if="form.domain" class="type-filter-info">
            <small>Showing only suites with domain: <strong>{{ form.domain }}</strong></small>
          </div>
          <div v-if="loadingSuites" class="loading">Loading test suites...</div>
          <div v-else-if="suitesError" class="error">{{ suitesError }}</div>
          <div v-else-if="availableSuites.length === 0" class="empty-state">
            <p>No test suites available. <router-link to="/tests/suites/new">Create a test suite first</router-link>.</p>
          </div>
          <div v-else class="selection-list">
            <div class="selection-header">
              <div class="col-checkbox"></div>
              <div class="col-name">Suite Name</div>
              <div class="col-application">Application</div>
              <div class="col-team">Team</div>
              <div class="col-type">Test Type</div>
            </div>
            <div class="selection-rows">
              <div
                v-for="suite in filteredSuites"
                :key="suite.id"
                class="selection-row"
                :class="{ 
                  'type-mismatch': form.domain && suite.domain !== form.domain,
                  'selected': form.testSuiteIds.includes(suite.id)
                }"
              >
                <div class="col-checkbox">
                  <input 
                    type="checkbox"
                    :value="suite.id"
                    v-model="form.testSuiteIds"
                    :disabled="form.domain && suite.domain !== form.domain"
                    class="suite-checkbox"
                  />
                </div>
                <div class="col-name">
                  <span class="suite-name">{{ suite.name }}</span>
                </div>
                <div class="col-application">
                  <span class="suite-application">{{ suite.application || 'N/A' }}</span>
                </div>
                <div class="col-team">
                  <span class="suite-team">{{ suite.team || 'N/A' }}</span>
                </div>
                <div class="col-type">
                  <span v-if="suite.domain" class="suite-type-badge">{{ suite.domain }}</span>
                  <span v-else class="suite-type-badge no-type">N/A</span>
                </div>
              </div>
            </div>
            <div v-if="form.domain && filteredSuites.length === 0" class="empty-state">
              <p>No test suites found with domain "{{ form.domain }}". <router-link to="/tests/suites/new">Create a test suite with this domain first</router-link>.</p>
            </div>
          </div>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Layers, Save, ArrowLeft } from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';

const router = useRouter();

const domainOptions = [
  { label: 'API Security', value: 'api_security' },
  { label: 'Platform Config', value: 'platform_config' },
  { label: 'Identity', value: 'identity' },
  { label: 'Data Contracts', value: 'data_contracts' },
  { label: 'Salesforce', value: 'salesforce' },
  { label: 'Elastic', value: 'elastic' },
  { label: 'IDP Platform', value: 'idp_platform' },
];

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Harnesses', to: '/tests/harnesses' },
  { label: 'Create Test Harness' },
];

const form = ref({
  name: '',
  description: '',
  team: '',
  domain: '' as string,
  testSuiteIds: [] as string[],
});

const availableSuites = ref<any[]>([]);
const loadingSuites = ref(false);
const suitesError = ref<string | null>(null);

const filteredSuites = computed(() => {
  if (!form.value.domain) {
    return availableSuites.value;
  }
  return availableSuites.value.filter(suite => suite.domain === form.value.domain);
});

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

const save = async () => {
  if (!form.value.domain) {
    alert('Please select a domain');
    return;
  }

  if (!form.value.name || !form.value.description) {
    alert('Please fill in all required fields');
    return;
  }

  saving.value = true;
  try {
    const payload: any = {
      name: form.value.name,
      description: form.value.description,
      team: form.value.team || undefined,
      domain: form.value.domain,
      testSuiteIds: form.value.testSuiteIds,
    };

    const response = await axios.post('/api/v1/test-harnesses', payload);
    await router.push({ path: `/tests/harnesses/${response.data.id || response.data._id}` });
  } catch (err: any) {
    console.error('Error saving harness:', err);
    alert(err.response?.data?.message || 'Failed to save test harness');
  } finally {
    saving.value = false;
  }
};

const goBack = () => {
  router.push('/tests/harnesses');
};

onMounted(() => {
  loadSuites();
});
</script>

<style scoped>
.test-harness-create-page {
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

.harness-form {
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

.form-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.5rem;
  margin-bottom: 1.5rem;
}

@media (max-width: 1600px) {
  .form-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 1400px) {
  .selection-header,
  .selection-row {
    grid-template-columns: auto 2fr 1.5fr 1fr;
    gap: 0.75rem;
  }
  
  .col-type {
    display: none;
  }
}

@media (max-width: 1200px) {
  .form-grid {
    grid-template-columns: 1fr;
  }
  
  .selection-header,
  .selection-row {
    grid-template-columns: auto 2fr 1fr;
    gap: 0.75rem;
    padding: 0.875rem 1.25rem;
  }
  
  .col-team,
  .col-type {
    display: none;
  }
}

@media (max-width: 900px) {
  .selection-header,
  .selection-row {
    grid-template-columns: auto 1fr;
    gap: 0.75rem;
    padding: 0.75rem 1rem;
  }
  
  .col-application,
  .col-team,
  .col-type {
    display: none;
  }
  
  .selection-header .col-name::after {
    content: ' (Application, Team, Type hidden on small screens)';
    font-size: var(--font-size-xs);
    font-weight: normal;
    opacity: 0.6;
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

.type-filter-info {
  margin-bottom: var(--spacing-base);
  padding: var(--spacing-xs);
  background: var(--border-color-muted);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
}

.type-filter-info strong {
  text-transform: capitalize;
}

.suite-type-badge {
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
}



.selection-list {
  display: flex;
  flex-direction: column;
  max-height: 600px;
  overflow-y: auto;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  background: var(--color-bg-overlay-light);
}

.selection-header {
  display: grid;
  grid-template-columns: auto 2fr 1.5fr 1.2fr 1.2fr;
  gap: var(--spacing-base);
  padding: var(--spacing-base) var(--spacing-lg);
  background: var(--border-color-muted);
  border-bottom: var(--border-width-medium) solid var(--border-color-primary);
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-sm);
  color: var(--color-primary);
  text-transform: uppercase;
  letter-spacing: var(--letter-spacing-wide);
  position: sticky;
  top: 0;
  z-index: 10;
}

.selection-rows {
  display: flex;
  flex-direction: column;
}

.selection-row {
  display: grid;
  grid-template-columns: auto 2fr 1.5fr 1.2fr 1.2fr;
  gap: var(--spacing-base);
  padding: var(--spacing-base) var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  transition: var(--transition-all);
  align-items: center;
  min-height: 60px;
  cursor: pointer;
}

.selection-row:nth-child(even) {
  background: var(--color-bg-overlay-light);
}

.selection-row:last-child {
  border-bottom: none;
}

.selection-row:hover:not(.type-mismatch) {
  background: var(--border-color-muted) !important;
  border-left: 3px solid var(--border-color-primary-active);
  transform: translateX(2px);
}

.selection-row.selected {
  background: var(--border-color-muted) !important;
  opacity: 0.15;
  border-left: 3px solid var(--color-primary);
}

.selection-row.selected:hover {
  background: var(--border-color-primary) !important;
  opacity: 0.2;
}

.selection-row.type-mismatch {
  opacity: var(--opacity-disabled);
  background: var(--color-bg-overlay-light) !important;
  cursor: not-allowed;
}

.selection-row.type-mismatch:hover {
  transform: none;
  border-left: none;
}

.col-checkbox {
  display: flex;
  align-items: center;
  justify-content: center;
}

.suite-checkbox {
  width: 22px;
  height: 22px;
  cursor: pointer;
  accent-color: var(--color-primary);
  flex-shrink: 0;
}

.suite-checkbox:disabled {
  cursor: not-allowed;
  opacity: var(--opacity-disabled);
}

.col-name {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-name {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  word-break: break-word;
  line-height: var(--line-height-normal);
}

.col-application,
.col-team {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-application,
.suite-team {
  color: var(--color-text-secondary);
  opacity: 0.8;
  font-size: var(--font-size-sm);
  word-break: break-word;
  line-height: var(--line-height-normal);
}

.col-type {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-type-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
  color: var(--color-primary);
  text-transform: capitalize;
}

.suite-type-badge.no-type {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-muted);
}

.loading,
.error,
.empty-state {
  padding: var(--spacing-md);
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

