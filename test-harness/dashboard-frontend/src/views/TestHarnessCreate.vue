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
              <label>Test Type *</label>
              <select v-model="form.testType" required class="form-input form-select">
                <option value="">Select a test type...</option>
                <option value="access-control">Access Control</option>
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
              <p class="field-help">All test suites in this harness must have the same test type.</p>
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
          <div v-if="form.testType" class="type-filter-info">
            <small>Showing only suites with type: <strong>{{ form.testType }}</strong></small>
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
                  'type-mismatch': form.testType && suite.testType !== form.testType,
                  'selected': form.testSuiteIds.includes(suite.id)
                }"
              >
                <div class="col-checkbox">
                  <input 
                    type="checkbox"
                    :value="suite.id"
                    v-model="form.testSuiteIds"
                    :disabled="form.testType && suite.testType !== form.testType"
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
                  <span v-if="suite.testType" class="suite-type-badge">{{ suite.testType }}</span>
                  <span v-else class="suite-type-badge no-type">N/A</span>
                </div>
              </div>
            </div>
            <div v-if="form.testType && filteredSuites.length === 0" class="empty-state">
              <p>No test suites found with type "{{ form.testType }}". <router-link to="/tests/suites/new">Create a test suite with this type first</router-link>.</p>
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

const router = useRouter();

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
  testType: '' as string,
  testSuiteIds: [] as string[],
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

const saving = ref(false);

const loadSuites = async () => {
  loadingSuites.value = true;
  suitesError.value = null;
  try {
    const response = await axios.get('/api/test-suites');
    availableSuites.value = response.data || [];
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to load test suites';
    console.error('Error loading suites:', err);
  } finally {
    loadingSuites.value = false;
  }
};

const save = async () => {
  if (!form.value.testType) {
    alert('Please select a test type');
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
      testType: form.value.testType,
      testSuiteIds: form.value.testSuiteIds,
    };

    const response = await axios.post('/api/test-harnesses', payload);
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

.harness-form {
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
    font-size: 0.7rem;
    font-weight: normal;
    opacity: 0.6;
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



.selection-list {
  display: flex;
  flex-direction: column;
  max-height: 600px;
  overflow-y: auto;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  background: rgba(15, 20, 25, 0.3);
}

.selection-header {
  display: grid;
  grid-template-columns: auto 2fr 1.5fr 1.2fr 1.2fr;
  gap: 1rem;
  padding: 1rem 1.5rem;
  background: rgba(79, 172, 254, 0.1);
  border-bottom: 2px solid rgba(79, 172, 254, 0.2);
  font-weight: 600;
  font-size: 0.875rem;
  color: #4facfe;
  text-transform: uppercase;
  letter-spacing: 0.5px;
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
  gap: 1rem;
  padding: 1rem 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  transition: all 0.2s;
  align-items: center;
  min-height: 60px;
  cursor: pointer;
}

.selection-row:nth-child(even) {
  background: rgba(15, 20, 25, 0.2);
}

.selection-row:last-child {
  border-bottom: none;
}

.selection-row:hover:not(.type-mismatch) {
  background: rgba(79, 172, 254, 0.1) !important;
  border-left: 3px solid rgba(79, 172, 254, 0.5);
  transform: translateX(2px);
}

.selection-row.selected {
  background: rgba(79, 172, 254, 0.15) !important;
  border-left: 3px solid #4facfe;
}

.selection-row.selected:hover {
  background: rgba(79, 172, 254, 0.2) !important;
}

.selection-row.type-mismatch {
  opacity: 0.5;
  background: rgba(15, 20, 25, 0.2) !important;
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
  accent-color: #4facfe;
  flex-shrink: 0;
}

.suite-checkbox:disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.col-name {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-name {
  font-weight: 600;
  color: #ffffff;
  font-size: 0.95rem;
  word-break: break-word;
  line-height: 1.4;
}

.col-application,
.col-team {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-application,
.suite-team {
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.875rem;
  word-break: break-word;
  line-height: 1.4;
}

.col-type {
  display: flex;
  align-items: center;
  min-width: 0;
}

.suite-type-badge {
  display: inline-block;
  padding: 0.35rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  font-size: 0.8rem;
  font-weight: 500;
  color: #4facfe;
  text-transform: capitalize;
}

.suite-type-badge.no-type {
  background: rgba(107, 114, 128, 0.2);
  color: #6b7280;
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

