<template>
  <div class="policies-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Salesforce Data Protection Baselines</h1>
          <p class="page-description">Manage Salesforce data protection baselines for HIPAA compliance</p>
        </div>
        <button @click="openCreateBaselineModal" class="btn-primary">
          <Plus class="btn-icon" />
          Create Baseline
        </button>
      </div>
    </div>

    <div v-if="loadingBaselines" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading baselines...</p>
    </div>

    <div v-else-if="baselinesError" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ baselinesError }}</p>
      <button @click="loadBaselines" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="baselines.length === 0" class="empty-state">
      <Cloud class="empty-icon" />
      <h3>No baselines defined</h3>
      <p>Create your first Salesforce data protection baseline to get started</p>
      <button @click="openCreateBaselineModal" class="btn-primary">Create First Baseline</button>
    </div>

    <div v-else class="baselines-grid">
      <div v-for="baseline in baselines" :key="baseline.id" class="baseline-card">
        <div class="baseline-header">
          <div>
            <h3 class="baseline-name">{{ baseline.name }}</h3>
            <div class="baseline-meta">
              <span class="baseline-environment">{{ baseline.environment || 'default' }}</span>
              <span class="baseline-version">v{{ baseline.version }}</span>
              <span v-if="baseline.isActive" class="baseline-active">Active</span>
            </div>
          </div>
        </div>
        <p class="baseline-description">{{ baseline.description || 'No description' }}</p>
        <div v-if="baseline.tags && baseline.tags.length > 0" class="baseline-tags">
          <span v-for="tag in baseline.tags" :key="tag" class="baseline-tag">{{ tag }}</span>
        </div>
        <div class="baseline-actions">
          <button @click="compareBaseline(baseline.id)" class="action-btn edit-btn">Compare</button>
          <button @click="detectDrift(baseline.id)" class="action-btn edit-btn">Detect Drift</button>
          <button @click="deleteBaseline(baseline.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <!-- Comparison Modal -->
    <BaselineComparison
      :visible="showComparisonModal"
      :baseline-id="selectedBaselineId"
      :baseline-name="selectedBaselineName"
      platform="salesforce"
      :current-config="currentConfig"
      @close="closeComparisonModal"
    />

    <!-- Drift Detection Modal -->
    <DriftDetection
      :visible="showDriftModal"
      :baseline-id="selectedBaselineId"
      :baseline-name="selectedBaselineName"
      platform="salesforce"
      :current-config="currentConfig"
      @close="closeDriftModal"
    />

    <!-- Create Baseline Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateBaselineModal" class="modal-overlay" @click="closeBaselineModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Cloud class="modal-title-icon" />
                <h2>Create Salesforce Data Protection Baseline</h2>
              </div>
              <button @click="closeBaselineModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveBaseline" class="form">
                <!-- Basic Information -->
                <div class="form-section">
                  <h3 class="section-title">Basic Information</h3>
                  <div class="form-group">
                    <label>Baseline Name *</label>
                    <input v-model="baselineForm.name" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Description</label>
                    <textarea v-model="baselineForm.description" rows="3"></textarea>
                  </div>
                  <div class="form-group">
                    <label>Environment *</label>
                    <select v-model="baselineForm.environment" required>
                      <option value="">Select environment...</option>
                      <option value="production">Production</option>
                      <option value="staging">Staging</option>
                      <option value="development">Development</option>
                      <option value="sandbox">Sandbox</option>
                    </select>
                  </div>
                </div>

                <!-- Encryption Settings -->
                <div class="form-section">
                  <h3 class="section-title">
                    <Shield class="section-icon" />
                    Encryption Settings
                  </h3>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.encryption.fieldEncryption.enabled" />
                      <span>Enable Field Encryption</span>
                    </label>
                    <p class="form-hint">Encrypt sensitive fields at rest (required for PHI)</p>
                  </div>
                  <div v-if="baselineForm.config.encryption.fieldEncryption.enabled" class="form-group">
                    <label>Key Management</label>
                    <select v-model="baselineForm.config.encryption.fieldEncryption.keyManagement">
                      <option value="Salesforce Managed">Salesforce Managed</option>
                      <option value="Customer Managed">Customer Managed</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.encryption.platformEncryption.enabled" />
                      <span>Enable Platform Encryption</span>
                    </label>
                    <p class="form-hint">Encrypt platform data at rest</p>
                  </div>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.encryption.shieldPlatformEncryption.enabled" />
                      <span>Enable Shield Platform Encryption</span>
                    </label>
                    <p class="form-hint">Advanced encryption for sensitive data</p>
                  </div>
                </div>

                <!-- Data Sharing Model -->
                <div class="form-section">
                  <h3 class="section-title">
                    <Users class="section-icon" />
                    Data Sharing Model
                  </h3>
                  <div class="form-group">
                    <label>Default Access Level</label>
                    <select v-model="baselineForm.config.sharingModel.defaultAccess">
                      <option value="Private">Private</option>
                      <option value="Public Read Only">Public Read Only</option>
                      <option value="Public Read/Write">Public Read/Write</option>
                    </select>
                    <p class="form-hint">Default sharing level for all objects (Private recommended for HIPAA)</p>
                  </div>
                </div>

                <!-- Audit Logging -->
                <div class="form-section">
                  <h3 class="section-title">
                    <FileText class="section-icon" />
                    Audit Logging & Compliance
                  </h3>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.loginAuditEnabled" />
                      <span>Enable Login Audit</span>
                    </label>
                  </div>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.dataAccessAuditEnabled" />
                      <span>Enable Data Access Audit</span>
                    </label>
                    <p class="form-hint">Required for HIPAA Security Rule compliance</p>
                  </div>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.hipaaCompliance.enabled" />
                      <span>Enable HIPAA Compliance Controls</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.auditLogging.hipaaCompliance.enabled" class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.hipaaCompliance.securityRuleControls" />
                      <span>Security Rule Controls</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.auditLogging.hipaaCompliance.enabled" class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.hipaaCompliance.privacyRuleControls" />
                      <span>Privacy Rule Controls</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.auditLogging.hipaaCompliance.enabled" class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.auditLogging.hipaaCompliance.breachNotificationRule" />
                      <span>Breach Notification Rule</span>
                    </label>
                  </div>
                </div>

                <!-- Data Retention -->
                <div class="form-section">
                  <h3 class="section-title">
                    <Clock class="section-icon" />
                    Data Retention
                  </h3>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.dataRetention.dataResidency.enabled" />
                      <span>Enable Data Residency Controls</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.dataRetention.dataResidency.enabled" class="form-group">
                    <label>Data Residency Region</label>
                    <input v-model="baselineForm.config.dataRetention.dataResidency.region" type="text" placeholder="e.g., US, EU" />
                  </div>
                </div>

                <!-- External Data Sharing -->
                <div class="form-section">
                  <h3 class="section-title">
                    <Share2 class="section-icon" />
                    External Data Sharing
                  </h3>
                  <div class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.externalDataSharing.dataExport.allowed" />
                      <span>Allow Data Export</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.externalDataSharing.dataExport.allowed" class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.externalDataSharing.dataExport.requireApproval" />
                      <span>Require Approval for Data Export</span>
                    </label>
                  </div>
                  <div v-if="baselineForm.config.externalDataSharing.dataExport.allowed" class="form-group">
                    <label class="checkbox-label">
                      <input type="checkbox" v-model="baselineForm.config.externalDataSharing.dataExport.encryptionRequired" />
                      <span>Require Encryption for Data Export</span>
                    </label>
                  </div>
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeBaselineModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">
                    Create Baseline
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
import { ref, onMounted, watch } from 'vue';
import { Teleport } from 'vue';
import {
  Cloud,
  Plus,
  Trash2,
  AlertTriangle,
  X,
  Shield,
  Users,
  FileText,
  Clock,
  Share2
} from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import BaselineComparison from '../../components/baselines/BaselineComparison.vue';
import DriftDetection from '../../components/baselines/DriftDetection.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Policies', to: '/policies' },
  { label: 'Salesforce Baselines' }
];

// Data
const baselines = ref<any[]>([]);
const loadingBaselines = ref(false);
const baselinesError = ref<string | null>(null);

// Modals
const showCreateBaselineModal = ref(false);
const showComparisonModal = ref(false);
const showDriftModal = ref(false);
const selectedBaselineId = ref<string | null>(null);
const selectedBaselineName = ref('');
const currentConfig = ref<Record<string, any>>({});

// Form
const baselineForm = ref({
  name: '',
  description: '',
  environment: '',
  config: {
    encryption: {
      fieldEncryption: {
        enabled: false,
        keyManagement: 'Salesforce Managed' as 'Salesforce Managed' | 'Customer Managed'
      },
      platformEncryption: {
        enabled: false,
        objects: [] as string[]
      },
      shieldPlatformEncryption: {
        enabled: false,
        encryptedFields: [] as string[]
      }
    },
    sharingModel: {
      defaultAccess: 'Private' as 'Private' | 'Public Read Only' | 'Public Read/Write'
    },
    auditLogging: {
      loginAuditEnabled: true,
      dataAccessAuditEnabled: true,
      hipaaCompliance: {
        enabled: false,
        securityRuleControls: false,
        privacyRuleControls: false,
        breachNotificationRule: false
      }
    },
    dataRetention: {
      dataResidency: {
        enabled: false,
        region: ''
      }
    },
    externalDataSharing: {
      dataExport: {
        allowed: false,
        requireApproval: false,
        encryptionRequired: false
      }
    }
  }
});

// API Calls
const loadBaselines = async () => {
  loadingBaselines.value = true;
  baselinesError.value = null;
  try {
    const response = await axios.get('/api/v1/salesforce/baselines');
    baselines.value = response.data || [];
  } catch (err: any) {
    baselinesError.value = err.response?.data?.message || 'Failed to load baselines';
    console.error('Error loading baselines:', err);
  } finally {
    loadingBaselines.value = false;
  }
};

// Actions
const openCreateBaselineModal = () => {
  baselineForm.value = {
    name: '',
    description: '',
    environment: '',
    config: {
      encryption: {
        fieldEncryption: {
          enabled: false,
          keyManagement: 'Salesforce Managed' as 'Salesforce Managed' | 'Customer Managed'
        },
        platformEncryption: {
          enabled: false,
          objects: []
        },
        shieldPlatformEncryption: {
          enabled: false,
          encryptedFields: []
        }
      },
      sharingModel: {
        defaultAccess: 'Private' as 'Private' | 'Public Read Only' | 'Public Read/Write'
      },
      auditLogging: {
        loginAuditEnabled: true,
        dataAccessAuditEnabled: true,
        hipaaCompliance: {
          enabled: false,
          securityRuleControls: false,
          privacyRuleControls: false,
          breachNotificationRule: false
        }
      },
      dataRetention: {
        dataResidency: {
          enabled: false,
          region: ''
        }
      },
      externalDataSharing: {
        dataExport: {
          allowed: false,
          requireApproval: false,
          encryptionRequired: false
        }
      }
    }
  };
  showCreateBaselineModal.value = true;
};

const closeBaselineModal = () => {
  showCreateBaselineModal.value = false;
};

const saveBaseline = async () => {
  try {
    const payload: any = {
      name: baselineForm.value.name,
      description: baselineForm.value.description,
      environment: baselineForm.value.environment,
      config: baselineForm.value.config
    };
    
    await axios.post('/api/v1/salesforce/baselines', payload);
    await loadBaselines();
    closeBaselineModal();
  } catch (err: any) {
    const errorMessage = err.response?.data?.message || err.response?.data?.error || 'Failed to create baseline';
    alert(errorMessage);
    console.error('Error creating baseline:', err);
  }
};

const compareBaseline = async (id: string) => {
  const baseline = baselines.value.find(b => b.id === id);
  if (baseline) {
    selectedBaselineId.value = id;
    selectedBaselineName.value = baseline.name;
    // In a real implementation, you would fetch current config from Salesforce API
    // For now, we'll use an empty object or allow user to paste config
    currentConfig.value = {};
    showComparisonModal.value = true;
  }
};

const detectDrift = async (id: string) => {
  const baseline = baselines.value.find(b => b.id === id);
  if (baseline) {
    selectedBaselineId.value = id;
    selectedBaselineName.value = baseline.name;
    // In a real implementation, you would fetch current config from Salesforce API
    currentConfig.value = {};
    showDriftModal.value = true;
  }
};

const closeComparisonModal = () => {
  showComparisonModal.value = false;
  selectedBaselineId.value = null;
  selectedBaselineName.value = '';
};

const closeDriftModal = () => {
  showDriftModal.value = false;
  selectedBaselineId.value = null;
  selectedBaselineName.value = '';
};

const deleteBaseline = async (id: string) => {
  if (confirm('Are you sure you want to delete this baseline?')) {
    try {
      await axios.delete(`/api/v1/salesforce/baselines/${id}`);
      await loadBaselines();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed to delete baseline');
      console.error('Error deleting baseline:', err);
    }
  }
};


onMounted(() => {
  loadBaselines();
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
  font-size: 1.1rem;
  color: var(--color-text-secondary);
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

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-icon {
  width: 18px;
  height: 18px;
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

.baselines-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: var(--spacing-lg);
}

.baseline-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.baseline-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.baseline-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.baseline-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.baseline-meta {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-xs);
  flex-wrap: wrap;
}

.baseline-environment {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.baseline-version {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  background: var(--border-color-muted);
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.baseline-active {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  background: var(--color-success-bg);
  color: var(--color-success);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.baseline-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.baseline-tags {
  display: flex;
  gap: var(--spacing-xs);
  flex-wrap: wrap;
  margin: var(--spacing-sm) 0;
}

.baseline-tag {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
}

.baseline-actions {
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
  max-width: 700px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-lg);
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
  padding: var(--spacing-xl);
  max-height: calc(90vh - 120px);
  overflow-y: auto;
}

.form {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  margin-bottom: var(--spacing-md);
}

.form-group:last-child {
  margin-bottom: 0;
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.label-optional {
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-normal);
  color: var(--color-text-secondary);
  font-style: italic;
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-dark);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  font-family: inherit;
  width: 100%;
}

.form-group input::placeholder,
.form-group textarea::placeholder {
  color: var(--color-text-secondary);
  opacity: 0.6;
}

.form-group textarea {
  resize: vertical;
  min-height: 80px;
}

.form-group select {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-dark);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
  font-family: inherit;
  width: 100%;
  cursor: pointer;
}

.form-group select:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.form-group select option {
  background: var(--color-bg-overlay-dark);
  color: var(--color-text-primary);
}

.checkbox-label {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  cursor: pointer;
  padding: var(--spacing-sm);
  border-radius: var(--border-radius-md);
  transition: var(--transition-all);
  margin: calc(var(--spacing-xs) * -1);
}

.checkbox-label:hover {
  background: var(--color-bg-overlay-light);
}

.checkbox-label input[type="checkbox"] {
  width: 20px;
  height: 20px;
  min-width: 20px;
  cursor: pointer;
  accent-color: var(--color-primary);
  margin-top: 2px;
}

.checkbox-label span {
  flex: 1;
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
  line-height: 1.5;
}

.form-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  margin-bottom: var(--spacing-md);
  transition: var(--transition-all);
}

.form-section:hover {
  border-color: var(--border-color-primary-hover);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.form-section:last-of-type {
  margin-bottom: 0;
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
  padding-bottom: var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.section-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.form-hint {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin: var(--spacing-xs) 0 0 0;
  line-height: 1.4;
  font-style: italic;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-md);
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.btn-secondary {
  padding: var(--spacing-md) var(--spacing-xl);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  font-size: var(--font-size-base);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
  color: var(--color-primary);
}

.btn-primary {
  padding: var(--spacing-md) var(--spacing-xl);
  font-size: var(--font-size-base);
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
