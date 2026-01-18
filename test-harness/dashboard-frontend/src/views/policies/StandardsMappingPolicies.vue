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
                  <input v-model="mappingForm.controlName" type="text" readonly :value="selectedControl.title" />
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
  { label: 'Policies', to: '/policies' },
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
    const response = await axios.get('/api/v1/policies');
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
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #4facfe;
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 24px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.loading-state p {
  color: #a0aec0;
  font-size: 1rem;
}

.error-state {
  text-align: center;
  padding: 40px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 12px;
  margin-bottom: 24px;
}

.error-icon {
  width: 48px;
  height: 48px;
  color: #fc8181;
  margin: 0 auto 16px;
}

.error-state p {
  color: #fc8181;
  font-size: 1rem;
  margin-bottom: 16px;
}

.btn-retry {
  padding: 10px 20px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-retry:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.empty-state {
  text-align: center;
  padding: 60px 40px;
  color: #a0aec0;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.empty-state p {
  margin: 0 0 24px 0;
}

.standards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.standard-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  transition: all 0.3s;
}

.standard-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.standard-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.standard-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.standard-version {
  padding: 4px 12px;
  border-radius: 12px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
}

.standard-description {
  color: #a0aec0;
  font-size: 0.9rem;
  margin: 12px 0;
  line-height: 1.5;
}

.standard-mappings {
  margin: 16px 0;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.mapping-count {
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
}

.standard-actions {
  display: flex;
  gap: 8px;
  margin-top: 16px;
}

.action-btn {
  padding: 8px 16px;
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  background: rgba(15, 20, 25, 0.6);
  color: #ffffff;
  cursor: pointer;
  font-size: 0.875rem;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(79, 172, 254, 0.1);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.edit-btn:hover {
  border-color: #4facfe;
  color: #4facfe;
}

.enable-btn:hover {
  border-color: #22c55e;
  color: #22c55e;
}

.delete-btn:hover {
  border-color: #fc8181;
  color: #fc8181;
}

/* Modal Styles */
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
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
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

.mappings-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.mapping-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.mapping-info h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.mapping-info p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 4px 0;
}

.mapping-control {
  font-weight: 500;
}

.mapping-type {
  display: flex;
  align-items: center;
  gap: 8px;
}

.type-badge {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.type-badge.type-direct {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.type-badge.type-partial {
  background: rgba(237, 137, 54, 0.1);
  color: #ed8936;
}

.type-badge.type-related {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.mapping-notes {
  font-style: italic;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.form {
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

.form-group textarea {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
  font-family: inherit;
  resize: vertical;
  min-height: 80px;
}

.form-group input[readonly] {
  background: rgba(15, 20, 25, 0.4);
  cursor: not-allowed;
  opacity: 0.7;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
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
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
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
