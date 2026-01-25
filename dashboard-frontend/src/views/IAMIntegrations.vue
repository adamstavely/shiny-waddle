<template>
  <div class="iam-integrations-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">IAM Integrations</h1>
          <p class="page-description">Manage SSO, RBAC, and Identity Provider integrations</p>
        </div>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
      </button>
    </div>

    <!-- SSO Tab -->
    <div v-if="activeTab === 'sso'" class="tab-content">
      <div class="tab-header">
        <h2>SSO Integrations</h2>
        <button @click="openCreateModal('sso')" class="btn-primary">
          <Plus class="btn-icon" />
          Add SSO Integration
        </button>
      </div>

      <div v-if="ssoIntegrations.length === 0" class="empty-state">
        <KeyRound class="empty-icon" />
        <h3>No SSO Integrations</h3>
        <p>Configure SSO to enable single sign-on authentication</p>
        <button @click="openCreateModal('sso')" class="btn-primary">
          <Plus class="btn-icon" />
          Add SSO Integration
        </button>
      </div>

      <div v-else class="integrations-grid">
        <div
          v-for="integration in ssoIntegrations"
          :key="integration.type"
          class="integration-card"
        >
          <div class="integration-card-header">
            <div class="integration-info">
              <KeyRound class="integration-icon" />
              <div>
                <h3 class="integration-name">{{ integration.type.toUpperCase() }}</h3>
                <span class="integration-type">{{ integration.type === 'saml' ? 'SAML 2.0' : 'OIDC' }}</span>
              </div>
            </div>
            <div class="integration-status">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  :checked="integration.enabled"
                  @change="toggleSSO(integration.type)"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">{{ integration.enabled ? 'Enabled' : 'Disabled' }}</span>
              </label>
            </div>
          </div>
          <div class="integration-card-content">
            <div class="integration-details">
              <div class="detail-item">
                <span class="detail-label">Endpoint</span>
                <span class="detail-value">{{ integration.endpoint }}</span>
              </div>
              <div v-if="integration.entityId" class="detail-item">
                <span class="detail-label">Entity ID</span>
                <span class="detail-value">{{ integration.entityId }}</span>
              </div>
              <div v-if="integration.clientId" class="detail-item">
                <span class="detail-label">Client ID</span>
                <span class="detail-value">{{ integration.clientId }}</span>
              </div>
            </div>
          </div>
          <div class="integration-card-actions">
            <button @click="generateAuthUrl(integration.type)" class="action-btn test-btn">
              <ExternalLink class="action-icon" />
              Generate Auth URL
            </button>
            <button @click="editIntegration('sso', integration)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteIntegration('sso', integration.type)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- RBAC Tab -->
    <div v-if="activeTab === 'rbac'" class="tab-content">
      <div class="tab-header">
        <h2>RBAC Integrations</h2>
        <button @click="openCreateModal('rbac')" class="btn-primary">
          <Plus class="btn-icon" />
          Add RBAC Integration
        </button>
      </div>

      <div v-if="rbacIntegrations.length === 0" class="empty-state">
        <Shield class="empty-icon" />
        <h3>No RBAC Integrations</h3>
        <p>Configure RBAC to manage roles and permissions from external systems</p>
        <button @click="openCreateModal('rbac')" class="btn-primary">
          <Plus class="btn-icon" />
          Add RBAC Integration
        </button>
      </div>

      <div v-else class="integrations-grid">
        <div
          v-for="integration in rbacIntegrations"
          :key="integration.provider"
          class="integration-card"
        >
          <div class="integration-card-header">
            <div class="integration-info">
              <Shield class="integration-icon" />
              <div>
                <h3 class="integration-name">{{ formatProvider(integration.provider) }}</h3>
                <span class="integration-type">RBAC Provider</span>
              </div>
            </div>
            <div class="integration-status">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  :checked="integration.enabled"
                  @change="toggleRBAC(integration.provider)"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">{{ integration.enabled ? 'Enabled' : 'Disabled' }}</span>
              </label>
            </div>
          </div>
          <div class="integration-card-content">
            <div class="integration-details">
              <div class="detail-item">
                <span class="detail-label">Endpoint</span>
                <span class="detail-value">{{ integration.endpoint }}</span>
              </div>
            </div>
          </div>
          <div class="integration-card-actions">
            <button @click="testRBAC(integration.provider)" class="action-btn test-btn">
              <CheckCircle2 class="action-icon" />
              Test Connection
            </button>
            <button @click="editIntegration('rbac', integration)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteIntegration('rbac', integration.provider)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- IdP Tab -->
    <div v-if="activeTab === 'idp'" class="tab-content">
      <div class="tab-header">
        <h2>Identity Provider Integrations</h2>
        <button @click="openCreateModal('idp')" class="btn-primary">
          <Plus class="btn-icon" />
          Add IdP Integration
        </button>
      </div>

      <div v-if="idpIntegrations.length === 0" class="empty-state">
        <Users class="empty-icon" />
        <h3>No Identity Provider Integrations</h3>
        <p>Configure identity providers to authenticate users</p>
        <button @click="openCreateModal('idp')" class="btn-primary">
          <Plus class="btn-icon" />
          Add IdP Integration
        </button>
      </div>

      <div v-else class="integrations-grid">
        <div
          v-for="integration in idpIntegrations"
          :key="integration.type"
          class="integration-card"
        >
          <div class="integration-card-header">
            <div class="integration-info">
              <Users class="integration-icon" />
              <div>
                <h3 class="integration-name">{{ formatIdPType(integration.type) }}</h3>
                <span class="integration-type">Identity Provider</span>
              </div>
            </div>
            <div class="integration-status">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  :checked="integration.enabled"
                  @change="toggleIdP(integration.type)"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">{{ integration.enabled ? 'Enabled' : 'Disabled' }}</span>
              </label>
            </div>
          </div>
          <div class="integration-card-content">
            <div class="integration-details">
              <div class="detail-item">
                <span class="detail-label">Endpoint</span>
                <span class="detail-value">{{ integration.endpoint }}</span>
              </div>
              <div class="detail-item">
                <span class="detail-label">Auth Type</span>
                <span class="detail-value">{{ integration.authentication?.type || 'N/A' }}</span>
              </div>
            </div>
          </div>
          <div class="integration-card-actions">
            <button @click="testIdP(integration.type)" class="action-btn test-btn">
              <CheckCircle2 class="action-icon" />
              Test Connection
            </button>
            <button @click="editIntegration('idp', integration)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click="deleteIntegration('idp', integration.type)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showModal" class="modal-overlay" @click="closeModal">
          <div class="modal-content large" @click.stop>
            <div class="modal-header">
              <h2>{{ editingIntegration ? `Edit ${modalType.toUpperCase()} Integration` : `Add ${modalType.toUpperCase()} Integration` }}</h2>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <!-- SSO Form -->
              <SSOConfigForm
                v-if="modalType === 'sso'"
                :config="ssoForm"
                @update:config="ssoForm = $event"
              />
              <!-- RBAC Form -->
              <RBACConfigForm
                v-if="modalType === 'rbac'"
                :config="rbacForm"
                @update:config="rbacForm = $event"
              />
              <!-- IdP Form -->
              <IdPConfigForm
                v-if="modalType === 'idp'"
                :config="idpForm"
                @update:config="idpForm = $event"
              />
              <div class="form-actions">
                <button type="button" @click="closeModal" class="btn-secondary">Cancel</button>
                <button type="button" @click="saveIntegration" class="btn-primary" :disabled="saving">
                  {{ saving ? 'Saving...' : editingIntegration ? 'Update' : 'Create' }}
                </button>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Teleport, Transition } from 'vue';
import {
  Plus,
  X,
  Edit,
  Trash2,
  CheckCircle2,
  KeyRound,
  Shield,
  Users,
  ExternalLink,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import SSOConfigForm from '../components/iam/SSOConfigForm.vue';
import RBACConfigForm from '../components/iam/RBACConfigForm.vue';
import IdPConfigForm from '../components/iam/IdPConfigForm.vue';
import type { SSOConfig, RBACConfig, IdPConfig } from '../types/iam';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'Integrations', to: '/admin/integrations' },
  { label: 'IAM Integrations' },
];

const API_BASE_URL = '/api/integrations/iam';

const activeTab = ref<'sso' | 'rbac' | 'idp'>('sso');
const tabs = [
  { id: 'sso', label: 'SSO', icon: KeyRound },
  { id: 'rbac', label: 'RBAC', icon: Shield },
  { id: 'idp', label: 'Identity Providers', icon: Users },
];

const ssoIntegrations = ref<SSOConfig[]>([]);
const rbacIntegrations = ref<RBACConfig[]>([]);
const idpIntegrations = ref<IdPConfig[]>([]);

const showModal = ref(false);
const modalType = ref<'sso' | 'rbac' | 'idp'>('sso');
const editingIntegration = ref<any>(null);
const saving = ref(false);

const ssoForm = ref<SSOConfig>({
  type: 'saml',
  enabled: true,
  endpoint: '',
});
const rbacForm = ref<RBACConfig>({
  provider: 'okta',
  enabled: true,
  endpoint: '',
});
const idpForm = ref<IdPConfig>({
  type: 'ldap',
  enabled: true,
  endpoint: '',
  authentication: {
    type: 'basic',
    credentials: {},
  },
});

const loadSSOIntegrations = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/sso`);
    ssoIntegrations.value = response.data || [];
  } catch (error) {
    console.error('Error loading SSO integrations:', error);
    ssoIntegrations.value = [];
  }
};

const loadRBACIntegrations = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/rbac`);
    rbacIntegrations.value = response.data || [];
  } catch (error) {
    console.error('Error loading RBAC integrations:', error);
    rbacIntegrations.value = [];
  }
};

const loadIdPIntegrations = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/idp`);
    idpIntegrations.value = response.data || [];
  } catch (error) {
    console.error('Error loading IdP integrations:', error);
    idpIntegrations.value = [];
  }
};

const openCreateModal = (type: 'sso' | 'rbac' | 'idp') => {
  modalType.value = type;
  editingIntegration.value = null;
  showModal.value = true;
  
  // Reset forms
  if (type === 'sso') {
    ssoForm.value = { type: 'saml', enabled: true, endpoint: '' };
  } else if (type === 'rbac') {
    rbacForm.value = { provider: 'okta', enabled: true, endpoint: '' };
  } else {
    idpForm.value = { type: 'ldap', enabled: true, endpoint: '', authentication: { type: 'basic', credentials: {} } };
  }
};

const editIntegration = (type: 'sso' | 'rbac' | 'idp', integration: any) => {
  modalType.value = type;
  editingIntegration.value = integration;
  showModal.value = true;
  
  if (type === 'sso') {
    ssoForm.value = { ...integration };
  } else if (type === 'rbac') {
    rbacForm.value = { ...integration };
  } else {
    idpForm.value = { ...integration };
  }
};

const closeModal = () => {
  showModal.value = false;
  editingIntegration.value = null;
};

const saveIntegration = async () => {
  saving.value = true;
  try {
    if (modalType.value === 'sso') {
      await axios.post(`${API_BASE_URL}/sso`, ssoForm.value);
      await loadSSOIntegrations();
    } else if (modalType.value === 'rbac') {
      await axios.post(`${API_BASE_URL}/rbac`, rbacForm.value);
      await loadRBACIntegrations();
    } else {
      await axios.post(`${API_BASE_URL}/idp`, idpForm.value);
      await loadIdPIntegrations();
    }
    closeModal();
  } catch (error: any) {
    alert(error.response?.data?.message || 'Failed to save integration');
  } finally {
    saving.value = false;
  }
};

const deleteIntegration = async (type: 'sso' | 'rbac' | 'idp', id: string) => {
  if (!confirm(`Are you sure you want to delete this ${type.toUpperCase()} integration?`)) {
    return;
  }
  
  try {
    // Note: Backend may not have DELETE endpoints, this is a placeholder
    alert('Delete functionality needs to be implemented in the backend');
  } catch (error) {
    alert('Failed to delete integration');
  }
};

const toggleSSO = async (type: string) => {
  const integration = ssoIntegrations.value.find(i => i.type === type);
  if (!integration) return;
  
  try {
    integration.enabled = !integration.enabled;
    await axios.post(`${API_BASE_URL}/sso`, integration);
    await loadSSOIntegrations();
  } catch (error) {
    alert('Failed to toggle integration');
  }
};

const toggleRBAC = async (provider: string) => {
  const integration = rbacIntegrations.value.find(i => i.provider === provider);
  if (!integration) return;
  
  try {
    integration.enabled = !integration.enabled;
    await axios.post(`${API_BASE_URL}/rbac`, integration);
    await loadRBACIntegrations();
  } catch (error) {
    alert('Failed to toggle integration');
  }
};

const toggleIdP = async (type: string) => {
  const integration = idpIntegrations.value.find(i => i.type === type);
  if (!integration) return;
  
  try {
    integration.enabled = !integration.enabled;
    await axios.post(`${API_BASE_URL}/idp`, integration);
    await loadIdPIntegrations();
  } catch (error) {
    alert('Failed to toggle integration');
  }
};

const generateAuthUrl = async (type: string) => {
  try {
    const response = await axios.get(`${API_BASE_URL}/sso/${type}/auth-url`);
    if (response.data?.url) {
      window.open(response.data.url, '_blank');
    } else {
      alert('Failed to generate auth URL');
    }
  } catch (error: any) {
    alert(error.response?.data?.message || 'Failed to generate auth URL');
  }
};

const testRBAC = async (provider: string) => {
  alert('RBAC connection testing needs to be implemented');
};

const testIdP = async (type: string) => {
  alert('IdP connection testing needs to be implemented');
};

const formatProvider = (provider: string): string => {
  return provider.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

const formatIdPType = (type: string): string => {
  return type.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
};

onMounted(() => {
  loadSSOIntegrations();
  loadRBACIntegrations();
  loadIdPIntegrations();
});
</script>

<style scoped>
.iam-integrations-page {
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
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
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  margin: 0 0 var(--spacing-sm) 0;
  color: var(--color-text-primary);
}

.page-description {
  color: var(--color-text-secondary);
  margin: 0;
}

.tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-size: 0.9rem;
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.tab-button:hover {
  color: var(--color-text-primary);
}

.tab-button.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  margin-top: var(--spacing-lg);
}

.tab-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.tab-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: 10px var(--spacing-xl);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-sm);
  color: var(--color-bg-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.integrations-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.integration-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
}

.integration-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.integration-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-xl);
}

.integration-info {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.integration-icon {
  width: 40px;
  height: 40px;
  color: var(--color-primary);
}

.integration-name {
  font-size: 1.1rem;
  font-weight: var(--font-weight-semibold);
  margin: 0 0 var(--spacing-xs) 0;
  color: var(--color-text-primary);
}

.integration-type {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.integration-status {
  display: flex;
  align-items: center;
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.toggle-input {
  display: none;
}

.toggle-slider {
  width: 44px;
  height: 24px;
  background: var(--color-info-bg);
  border-radius: var(--border-radius-lg);
  position: relative;
  transition: background 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 20px;
  height: 20px;
  background: var(--color-primary);
  border-radius: 50%;
  top: 2px;
  left: 2px;
  transition: transform 0.2s;
}

.toggle-input:checked + .toggle-slider {
  background: rgba(79, 172, 254, 0.4);
}

.toggle-input:checked + .toggle-slider::before {
  transform: translateX(20px);
}

.toggle-text {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.integration-card-content {
  margin-bottom: var(--spacing-xl);
}

.integration-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.detail-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.detail-value {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.integration-card-actions {
  display: flex;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-xl);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.action-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--border-radius-sm);
  border: none;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.test-btn {
  background: rgba(79, 172, 254, 0.1);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.test-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.edit-btn {
  background: rgba(79, 172, 254, 0.1);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-secondary);
}

.edit-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.delete-btn {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
}

.delete-btn:hover {
  background: var(--color-error-bg);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-xl) var(--spacing-lg);
  background: var(--gradient-card);
  border: var(--border-width-thin) dashed var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-text-muted);
  margin: 0 auto var(--spacing-lg);
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  margin: 0 0 var(--spacing-sm) 0;
  color: var(--color-text-primary);
}

.empty-state p {
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-lg) 0;
}

/* Modal styles */
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
  padding: var(--spacing-lg);
}

.modal-content {
  background: var(--gradient-card);
  border-radius: var(--border-radius-lg);
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.modal-content.large {
  max-width: 800px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  margin: 0;
  color: var(--color-text-primary);
}

.modal-close {
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-xs);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: var(--color-text-primary);
}

.close-icon {
  width: 24px;
  height: 24px;
}

.modal-body {
  padding: 24px;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-secondary {
  padding: 10px 20px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
</style>

