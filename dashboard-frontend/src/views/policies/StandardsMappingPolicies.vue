<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Standards Mapping</h1>
          <p class="page-description">Map policies to compliance standards</p>
        </div>
      </div>
    </div>

    <div v-if="loadingStandards" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading standards...</p>
    </div>

    <div v-else-if="standardsError" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ standardsError }}</p>
      <button @click="loadStandards" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="standards.length === 0" class="empty-state">
      <CheckCircle2 class="empty-icon" />
      <h3>No compliance standards available</h3>
      <p>Standards will appear here when configured</p>
    </div>

    <div v-else class="standards-grid">
      <div v-for="standard in standards" :key="standard.id" class="standard-card">
        <div class="standard-header">
          <h3 class="standard-name">{{ standard.name }}</h3>
          <span class="standard-version">{{ standard.version }}</span>
        </div>
        <p class="standard-description">{{ standard.description || 'No description' }}</p>
        <div class="standard-mappings">
          <span class="mapping-count">{{ getMappingCount(standard.id) }} policy mapping{{ getMappingCount(standard.id) !== 1 ? 's' : '' }}</span>
        </div>
        <div class="standard-actions">
          <button @click="viewMappings(standard)" class="action-btn edit-btn">
            <FileText class="action-icon" />
            View Mappings
          </button>
          <button @click="openCreateMappingModal(standard)" class="action-btn enable-btn">
            <Plus class="action-icon" />
            Add Mapping
          </button>
        </div>
      </div>
    </div>

    <!-- View Mappings Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showMappingsModal && selectedStandard" class="modal-overlay" @click="closeMappingsModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <CheckCircle2 class="modal-title-icon" />
                <h2>Mappings for {{ selectedStandard.name }}</h2>
              </div>
              <button @click="closeMappingsModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="loadingMappings" class="loading-state">
                <div class="loading-spinner"></div>
                <p>Loading mappings...</p>
              </div>
              <div v-else-if="currentMappings.length === 0" class="empty-state">
                <p>No mappings found for this standard</p>
                <button @click="openCreateMappingModal(selectedStandard)" class="btn-primary">
                  Create First Mapping
                </button>
              </div>
              <div v-else class="mappings-list">
                <div v-for="mapping in currentMappings" :key="mapping.id" class="mapping-item">
                  <div class="mapping-info">
                    <h4>{{ getPolicyName(mapping.policyId) }}</h4>
                    <p class="mapping-control">
                      <strong>Control:</strong> {{ mapping.controlId }} - {{ mapping.controlName }}
                    </p>
                    <p class="mapping-type">
                      <strong>Type:</strong> <span class="type-badge" :class="`type-${mapping.mappingType}`">{{ mapping.mappingType }}</span>
                    </p>
                    <p v-if="mapping.notes" class="mapping-notes">{{ mapping.notes }}</p>
                  </div>
                  <button @click="deleteMapping(selectedStandard.id, mapping.id)" class="action-btn delete-btn">
                    <Trash2 class="action-icon" />
                    Delete
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Create Mapping Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateMappingModal && selectedStandard" class="modal-overlay" @click="closeCreateMappingModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <CheckCircle2 class="modal-title-icon" />
                <h2>Create Mapping for {{ selectedStandard.name }}</h2>
              </div>
              <button @click="closeCreateMappingModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveMapping" class="form">
                <div class="form-group">
                  <label>Policy</label>
                  <Dropdown
                    v-model="mappingForm.policyId"
                    :options="policyOptions"
                    placeholder="Select a policy..."
                  />
                </div>
                <div class="form-group">
                  <label>Control</label>
                  <Dropdown
                    v-model="mappingForm.controlId"
                    :options="controlOptions"
                    placeholder="Select a control..."
                    @update:modelValue="onControlSelected"
                  />
                </div>
                <div v-if="selectedControl" class="form-group">
                  <label>Control Name</label>
                  <input v-model="mappingForm.controlName" type="text" readonly />
                </div>
                <div class="form-group">
                  <label>Mapping Type</label>
                  <Dropdown
                    v-model="mappingForm.mappingType"
                    :options="mappingTypeOptions"
                    placeholder="Select mapping type..."
                  />
                </div>
                <div class="form-group">
                  <label>Notes (Optional)</label>
                  <textarea v-model="mappingForm.notes" rows="3" placeholder="Additional notes about this mapping"></textarea>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeCreateMappingModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="!mappingForm.policyId || !mappingForm.controlId || !mappingForm.mappingType">
                    Create Mapping
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  CheckCircle2,
  Plus,
  FileText,
  Trash2,
  AlertTriangle,
  X
} from 'lucide-vue-next';
import Dropdown from '../../components/Dropdown.vue';
import Breadcrumb from '../../components/Breadcrumb.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'Standards Mapping' }
];

// Data
const standards = ref<any[]>([]);
const mappings = ref<any[]>([]);
const policies = ref<any[]>([]);
const controls = ref<any[]>([]);
const loadingStandards = ref(false);
const loadingMappings = ref(false);
const loadingPolicies = ref(false);
const loadingControls = ref(false);
const standardsError = ref<string | null>(null);
const mappingsError = ref<string | null>(null);

// Modals
const showMappingsModal = ref(false);
const showCreateMappingModal = ref(false);
const selectedStandard = ref<any>(null);
const currentMappings = ref<any[]>([]);
const selectedControl = ref<any>(null);

// Forms
const mappingForm = ref({
  policyId: '',
  controlId: '',
  controlName: '',
  mappingType: '' as 'direct' | 'partial' | 'related' | '',
  notes: ''
});

// Options
const policyOptions = computed(() =>
  policies.value.map(policy => ({ label: `${policy.name} (${policy.type.toUpperCase()})`, value: policy.id }))
);

const controlOptions = computed(() =>
  controls.value.map(control => ({ 
    label: `${control.controlId}: ${control.title}`, 
    value: control.controlId 
  }))
);

const mappingTypeOptions = [
  { label: 'Direct', value: 'direct' },
  { label: 'Partial', value: 'partial' },
  { label: 'Related', value: 'related' }
];

const getMappingCount = (standardId: string): number => {
  return mappings.value.filter(m => m.standardId === standardId).length;
};

const getPolicyName = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.name || 'Unknown Policy';
};

// API Calls
const loadStandards = async () => {
  loadingStandards.value = true;
  standardsError.value = null;
  try {
    const response = await axios.get('/api/v1/standards');
    standards.value = response.data || [];
    await loadMappings();
  } catch (err: any) {
    standardsError.value = err.response?.data?.message || 'Failed to load standards';
    console.error('Error loading standards:', err);
  } finally {
    loadingStandards.value = false;
  }
};

const loadMappings = async () => {
  loadingMappings.value = true;
  mappingsError.value = null;
  try {
    const allMappings: any[] = [];
    for (const standard of standards.value) {
      try {
        const response = await axios.get(`/api/v1/standards/${standard.id}/mappings`);
        allMappings.push(...(response.data || []).map((m: any) => ({ ...m, standardId: standard.id })));
      } catch (err) {
        console.error(`Error loading mappings for ${standard.id}:`, err);
      }
    }
    mappings.value = allMappings;
  } catch (err: any) {
    mappingsError.value = err.response?.data?.message || 'Failed to load mappings';
    console.error('Error loading mappings:', err);
  } finally {
    loadingMappings.value = false;
  }
};

const loadPolicies = async () => {
  loadingPolicies.value = true;
  try {
    const response = await axios.get('/api/policies');
    policies.value = response.data || [];
  } catch (err: any) {
    console.error('Error loading policies:', err);
  } finally {
    loadingPolicies.value = false;
  }
};

// Actions
const viewMappings = async (standard: any) => {
  selectedStandard.value = standard;
  loadingMappings.value = true;
  try {
    const response = await axios.get(`/api/v1/standards/${standard.id}/mappings`);
    currentMappings.value = response.data || [];
    showMappingsModal.value = true;
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to load mappings');
    console.error('Error loading mappings:', err);
  } finally {
    loadingMappings.value = false;
  }
};

const closeMappingsModal = () => {
  showMappingsModal.value = false;
  selectedStandard.value = null;
  currentMappings.value = [];
};

const openCreateMappingModal = async (standard: any) => {
  selectedStandard.value = standard;
  mappingForm.value = {
    policyId: '',
    controlId: '',
    controlName: '',
    mappingType: '',
    notes: ''
  };
  selectedControl.value = null;
  await loadControlsForStandard(standard);
  showCreateMappingModal.value = true;
  closeMappingsModal();
};

const loadControlsForStandard = async (standard: any) => {
  if (!standard?.framework) return;
  
  loadingControls.value = true;
  try {
    // Map framework names from standards to compliance framework enum values
    const frameworkMap: Record<string, string> = {
      'nist': 'nist_800_53_rev_5',
      'soc2': 'soc_2',
      'iso27001': 'iso_27001',
      'pci-dss': 'pci_dss',
      'hipaa': 'hipaa',
      'gdpr': 'gdpr'
    };
    
    const framework = frameworkMap[standard.framework] || standard.framework;
    const response = await axios.get(`/api/v1/compliance/frameworks/${framework}/controls`);
    controls.value = response.data || [];
  } catch (err: any) {
    console.error('Error loading controls:', err);
    controls.value = [];
  } finally {
    loadingControls.value = false;
  }
};

const onControlSelected = (controlId: string) => {
  const control = controls.value.find(c => c.controlId === controlId);
  if (control) {
    selectedControl.value = control;
    mappingForm.value.controlName = control.title;
  }
};

const closeCreateMappingModal = () => {
  showCreateMappingModal.value = false;
  selectedStandard.value = null;
};

const saveMapping = async () => {
  if (!selectedStandard.value || !mappingForm.value.policyId || !mappingForm.value.controlId || !mappingForm.value.mappingType) return;
  
  try {
    await axios.post(`/api/v1/standards/${selectedStandard.value.id}/mappings`, {
      policyId: mappingForm.value.policyId,
      controlId: mappingForm.value.controlId,
      controlName: mappingForm.value.controlName,
      mappingType: mappingForm.value.mappingType,
      notes: mappingForm.value.notes || undefined
    });
    await loadMappings();
    closeCreateMappingModal();
  } catch (err: any) {
    alert(err.response?.data?.message || 'Failed to create mapping');
    console.error('Error creating mapping:', err);
  }
};

const deleteMapping = async (standardId: string, mappingId: string) => {
  if (confirm('Are you sure you want to delete this mapping?')) {
    try {
      await axios.delete(`/api/v1/standards/${standardId}/mappings/${mappingId}`);
      await loadMappings();
      if (showMappingsModal.value && selectedStandard.value?.id === standardId) {
        await viewMappings(selectedStandard.value);
      }
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete mapping');
      console.error('Error deleting mapping:', err);
    }
  }
};

// Load data on mount
onMounted(() => {
  loadPolicies();
  loadStandards();
});
</script>

<style scoped>
.policies-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: var(--spacing-xl);
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

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-primary);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto var(--spacing-lg);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.error-state {
  text-align: center;
  padding: var(--spacing-2xl);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-lg);
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.error-state p {
  color: var(--color-error);
  font-size: var(--font-size-base);
  margin-bottom: var(--spacing-md);
}

.btn-retry {
  padding: var(--spacing-sm) var(--spacing-xl);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-retry:hover {
  background: var(--border-color-primary);
  opacity: 0.2;
  border-color: var(--border-color-primary-active);
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.standards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: var(--spacing-lg);
}

.standard-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.standard-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.standard-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.standard-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.standard-version {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.standard-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.standard-mappings {
  margin: var(--spacing-md) 0;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
}

.mapping-count {
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.standard-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-md);
}

.action-btn {
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  transition: var(--transition-all);
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  border-color: var(--border-color-primary-hover);
  background: var(--border-color-muted);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.edit-btn:hover {
  border-color: var(--color-primary);
  color: var(--color-primary);
}

.enable-btn:hover {
  border-color: var(--color-success);
  color: var(--color-success);
}

.delete-btn:hover {
  border-color: var(--color-error);
  color: var(--color-error);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
}

.mappings-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.mapping-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.mapping-info h4 {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.mapping-info p {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0;
}

.mapping-control {
  font-weight: var(--font-weight-medium);
}

.mapping-type {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.type-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.type-badge.type-direct {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.type-badge.type-partial {
  background: var(--color-warning-bg);
  color: var(--color-warning-dark);
}

.type-badge.type-related {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.mapping-notes {
  font-style: italic;
  margin-top: var(--spacing-sm);
  padding-top: var(--spacing-sm);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
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

.form-group textarea {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  font-family: inherit;
  resize: vertical;
  min-height: 80px;
}

.form-group input[readonly] {
  background: var(--color-bg-overlay-light);
  cursor: not-allowed;
  opacity: var(--opacity-disabled);
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: 8px;
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
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
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
