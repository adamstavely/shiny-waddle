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
  font-size: 2rem;
  font-weight: 700;
  margin: 0 0 8px 0;
  color: #fff;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #ffffff;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  margin-top: 24px;
}

.tab-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.tab-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  transition: all 0.2s;
}

.integration-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.integration-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
}

.integration-info {
  display: flex;
  align-items: center;
  gap: 12px;
}

.integration-icon {
  width: 40px;
  height: 40px;
  color: #4facfe;
}

.integration-name {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 4px 0;
  color: #fff;
}

.integration-type {
  font-size: 0.75rem;
  color: #718096;
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
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  position: relative;
  transition: background 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 20px;
  height: 20px;
  background: #4facfe;
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
  font-size: 0.875rem;
  color: #a0aec0;
}

.integration-card-content {
  margin-bottom: 20px;
}

.integration-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
}

.detail-value {
  font-size: 0.875rem;
  color: #fff;
  font-weight: 500;
}

.integration-card-actions {
  display: flex;
  gap: 8px;
  padding-top: 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.action-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: 6px;
  border: none;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.test-btn {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.test-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.edit-btn {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.edit-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.delete-btn {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.2);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 64px 24px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px dashed rgba(79, 172, 254, 0.3);
  border-radius: 12px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #718096;
  margin: 0 auto 24px;
}

.empty-state h3 {
  font-size: 1.5rem;
  margin: 0 0 8px 0;
  color: #fff;
}

.empty-state p {
  color: #a0aec0;
  margin: 0 0 24px 0;
}

/* Modal styles */
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
  padding: 24px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border-radius: 12px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.5);
}

.modal-content.large {
  max-width: 800px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  margin: 0;
  color: #fff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #fff;
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

