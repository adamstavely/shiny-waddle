<template>
  <div class="ticketing-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Ticketing Integrations</h1>
          <p class="page-description">Connect and manage ticketing system integrations for automated violation tracking</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Add Integration
        </button>
      </div>
    </div>

    <!-- Integrations List -->
    <div class="integrations-grid">
      <div
        v-for="integration in integrations"
        :key="integration.id"
        class="integration-card"
        :class="`integration-${integration.provider}`"
      >
        <div class="integration-card-header">
          <div class="integration-info">
            <component :is="getProviderIcon(integration.provider)" class="integration-icon" />
            <div>
              <h3 class="integration-name">{{ integration.name }}</h3>
              <span class="integration-provider">{{ integration.provider.toUpperCase() }}</span>
            </div>
          </div>
          <div class="integration-status">
            <label class="toggle-label">
              <input
                type="checkbox"
                :checked="integration.enabled"
                @change="toggleIntegration(integration.id)"
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
              <span class="detail-label">Base URL</span>
              <span class="detail-value">{{ integration.config.baseUrl }}</span>
            </div>
            <div v-if="integration.config.projectKey" class="detail-item">
              <span class="detail-label">Project Key</span>
              <span class="detail-value">{{ integration.config.projectKey }}</span>
            </div>
            <div v-if="integration.config.repository" class="detail-item">
              <span class="detail-label">Repository</span>
              <span class="detail-value">{{ integration.config.repository }}</span>
            </div>
          </div>
        </div>
        <div class="integration-card-actions">
          <button @click="testConnection(integration.id)" class="action-btn test-btn" :disabled="testing === integration.id">
            <CheckCircle2 v-if="testing !== integration.id" class="action-icon" />
            <Loader2 v-else class="action-icon spinning" />
            {{ testing === integration.id ? 'Testing...' : 'Test Connection' }}
          </button>
          <button @click="editIntegration(integration)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click="deleteIntegration(integration.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="integrations.length === 0" class="empty-state">
      <Ticket class="empty-icon" />
      <h3>No Ticketing Integrations</h3>
      <p>Connect a ticketing system to automatically create tickets for violations</p>
      <button @click="showCreateModal = true" class="btn-primary">
        <Plus class="btn-icon" />
        Add Integration
      </button>
    </div>

    <!-- Create/Edit Integration Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showCreateModal || editingIntegration" class="modal-overlay" @click="closeModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h2>{{ editingIntegration ? 'Edit Integration' : 'Add Ticketing Integration' }}</h2>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <form @submit.prevent="saveIntegration" class="modal-body">
              <div class="form-group">
                <label>Provider</label>
                <Dropdown
                  v-model="form.provider"
                  :options="providerOptions"
                  placeholder="Select provider"
                  :disabled="!!editingIntegration"
                />
              </div>
              <div class="form-group">
                <label>Name</label>
                <input v-model="form.name" type="text" placeholder="Integration name" required />
              </div>
              <div class="form-group">
                <label>Base URL</label>
                <input v-model="form.config.baseUrl" type="url" placeholder="https://example.atlassian.net" required />
              </div>
              <div class="form-group">
                <label>API Token</label>
                <input v-model="form.config.apiToken" type="password" placeholder="API token" required />
              </div>

              <!-- Jira-specific fields -->
              <template v-if="form.provider === 'jira'">
                <div class="form-group">
                  <label>Email</label>
                  <input v-model="form.config.jira.email" type="email" placeholder="your-email@example.com" required />
                </div>
                <div class="form-group">
                  <label>Project Key</label>
                  <input v-model="form.config.projectKey" type="text" placeholder="PROJ" required />
                </div>
                <div class="form-group">
                  <label>Issue Type</label>
                  <input v-model="form.config.jira.issueType" type="text" placeholder="Bug" />
                </div>
              </template>

              <!-- ServiceNow-specific fields -->
              <template v-if="form.provider === 'servicenow'">
                <div class="form-group">
                  <label>Instance</label>
                  <input v-model="form.config.servicenow.instance" type="text" placeholder="your-instance" required />
                </div>
                <div class="form-group">
                  <label>Username</label>
                  <input v-model="form.config.servicenow.username" type="text" placeholder="username" required />
                </div>
                <div class="form-group">
                  <label>Password</label>
                  <input v-model="form.config.servicenow.password" type="password" placeholder="password" required />
                </div>
                <div class="form-group">
                  <label>Table Name</label>
                  <input v-model="form.config.servicenow.tableName" type="text" placeholder="incident" />
                </div>
              </template>

              <!-- GitHub-specific fields -->
              <template v-if="form.provider === 'github'">
                <div class="form-group">
                  <label>Owner</label>
                  <input v-model="form.config.github.owner" type="text" placeholder="organization" required />
                </div>
                <div class="form-group">
                  <label>Repository</label>
                  <input v-model="form.config.github.repo" type="text" placeholder="repo-name" required />
                </div>
                <div class="form-group">
                  <label>Labels (comma-separated)</label>
                  <input v-model="form.config.github.labels" type="text" placeholder="security, violation" />
                </div>
              </template>

              <div class="form-group">
                <label class="checkbox-label">
                  <input v-model="form.enabled" type="checkbox" class="checkbox-input" />
                  <span>Enable integration</span>
                </label>
              </div>

              <div class="form-actions">
                <button type="button" @click="closeModal" class="btn-secondary">Cancel</button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  {{ saving ? 'Saving...' : editingIntegration ? 'Update' : 'Create' }}
                </button>
              </div>
            </form>
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
  Loader2,
  Ticket,
  Settings,
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import type { TicketingIntegration, TicketingProvider } from '../types/ticketing';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'Ticketing Integrations' },
];

const API_BASE_URL = '/api';

const integrations = ref<TicketingIntegration[]>([]);
const showCreateModal = ref(false);
const editingIntegration = ref<TicketingIntegration | null>(null);
const saving = ref(false);
const testing = ref<string | null>(null);

const form = ref({
  provider: '' as TicketingProvider | '',
  name: '',
  enabled: true,
  config: {
    baseUrl: '',
    apiToken: '',
    projectKey: '',
    jira: {
      email: '',
      apiToken: '',
      issueType: 'Bug',
    },
    servicenow: {
      instance: '',
      username: '',
      password: '',
      tableName: 'incident',
    },
    github: {
      owner: '',
      repo: '',
      labels: '',
    },
  },
});

const providerOptions = [
  { label: 'Jira', value: 'jira' },
  { label: 'ServiceNow', value: 'servicenow' },
  { label: 'GitHub', value: 'github' },
];

const getProviderIcon = (provider: TicketingProvider) => {
  return Ticket; // You can use different icons per provider
};

const loadIntegrations = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/ticketing/integrations`);
    integrations.value = response.data;
  } catch (error) {
    console.error('Error loading integrations:', error);
  }
};

const saveIntegration = async () => {
  saving.value = true;
  try {
    const payload = {
      ...form.value,
      config: {
        ...form.value.config,
        ...(form.value.provider === 'jira' && {
          jira: form.value.config.jira,
        }),
        ...(form.value.provider === 'servicenow' && {
          servicenow: form.value.config.servicenow,
        }),
        ...(form.value.provider === 'github' && {
          github: {
            ...form.value.config.github,
            labels: form.value.config.github.labels?.split(',').map(l => l.trim()) || [],
          },
        }),
      },
    };

    if (editingIntegration.value) {
      await axios.patch(`${API_BASE_URL}/ticketing/integrations/${editingIntegration.value.id}`, payload);
    } else {
      await axios.post(`${API_BASE_URL}/ticketing/integrations`, payload);
    }

    await loadIntegrations();
    closeModal();
  } catch (error: any) {
    alert(error.response?.data?.message || 'Failed to save integration');
  } finally {
    saving.value = false;
  }
};

const editIntegration = (integration: TicketingIntegration) => {
  editingIntegration.value = integration;
  form.value = {
    provider: integration.provider,
    name: integration.name,
    enabled: integration.enabled,
    config: {
      baseUrl: integration.config.baseUrl,
      apiToken: integration.config.apiToken,
      projectKey: integration.config.projectKey || '',
      jira: integration.config.jira || { email: '', apiToken: '', issueType: 'Bug' },
      servicenow: integration.config.servicenow || { instance: '', username: '', password: '', tableName: 'incident' },
      github: {
        owner: integration.config.github?.owner || '',
        repo: integration.config.github?.repo || '',
        labels: integration.config.github?.labels?.join(', ') || '',
      },
    },
  };
  showCreateModal.value = true;
};

const deleteIntegration = async (id: string) => {
  if (!confirm('Are you sure you want to delete this integration?')) {
    return;
  }

  try {
    await axios.delete(`${API_BASE_URL}/ticketing/integrations/${id}`);
    await loadIntegrations();
  } catch (error) {
    alert('Failed to delete integration');
  }
};

const toggleIntegration = async (id: string) => {
  const integration = integrations.value.find(i => i.id === id);
  if (!integration) return;

  try {
    await axios.patch(`${API_BASE_URL}/ticketing/integrations/${id}`, {
      enabled: !integration.enabled,
    });
    await loadIntegrations();
  } catch (error) {
    alert('Failed to update integration');
  }
};

const testConnection = async (id: string) => {
  testing.value = id;
  try {
    const response = await axios.post(`${API_BASE_URL}/ticketing/integrations/${id}/test`);
    if (response.data.success) {
      alert('Connection test successful!');
    } else {
      alert('Connection test failed');
    }
  } catch (error: any) {
    alert(error.response?.data?.message || 'Connection test failed');
  } finally {
    testing.value = null;
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingIntegration.value = null;
  form.value = {
    provider: '' as TicketingProvider | '',
    name: '',
    enabled: true,
    config: {
      baseUrl: '',
      apiToken: '',
      projectKey: '',
      jira: { email: '', apiToken: '', issueType: 'Bug' },
      servicenow: { instance: '', username: '', password: '', tableName: 'incident' },
      github: { owner: '', repo: '', labels: '' },
    },
  };
};

onMounted(() => {
  loadIntegrations();
});
</script>

<style scoped>
.ticketing-page {
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
  font-size: 2rem;
  font-weight: 700;
  margin: 0 0 8px 0;
  color: #fff;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.integrations-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
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

.integration-provider {
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

.test-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.2);
}

.test-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
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

.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
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

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-group input {
  width: 100%;
  padding: 10px 12px;
  background: rgba(15, 20, 25, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #fff;
  font-size: 0.9rem;
}

.form-group input:focus {
  outline: none;
  border-color: #4facfe;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-primary,
.btn-secondary {
  padding: 10px 20px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #fff;
  border: none;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
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

.btn-icon {
  width: 18px;
  height: 18px;
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

