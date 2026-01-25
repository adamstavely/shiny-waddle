<template>
  <div class="admin-applications-tab">
    <div class="section-header">
      <div>
        <h2 class="section-title">
          <Layers class="title-icon" />
          Registered Applications
        </h2>
        <p class="section-description">
          Register and manage applications that Heimdall will test against
        </p>
      </div>
      <BaseButton label="Register Application" :icon="Plus" @click="showCreateModal = true" />
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading">Loading applications...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <BaseButton label="Retry" @click="loadApplications" />
    </div>
    <div v-else-if="applications.length === 0" class="empty-state">
      <EmptyState
        title="No applications registered"
        description="Register your first application to start running compliance tests"
        :icon="Layers"
        action-label="Register Application"
        :show-default-action="true"
        @action="showCreateModal = true"
      />
    </div>
    <div v-else class="applications-grid">
      <div
        v-for="app in applications"
        :key="app.id"
        class="application-card"
      >
        <div class="app-header">
          <div class="app-title-row">
            <h3 class="app-name">{{ app.name }}</h3>
            <div class="app-status-badges">
              <StatusBadge :status="app.status" />
              <StatusBadge
                v-if="getLatestResult(app.id)"
                :status="getLatestResult(app.id).status"
                size="sm"
              />
              <StatusBadge
                v-else
                status="never"
                label="Never tested"
                size="sm"
              />
            </div>
          </div>
          <p class="app-id">ID: {{ app.id }}</p>
        </div>

        <div class="app-details">
          <div class="detail-item">
            <span class="detail-label">Type</span>
            <span class="detail-value">{{ app.type }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Base URL</span>
            <span class="detail-value">{{ app.baseUrl || 'N/A' }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Team</span>
            <span class="detail-value">{{ app.team || 'Unassigned' }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Registered</span>
            <span class="detail-value">{{ formatDate(app.registeredAt) }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Last Test</span>
            <span class="detail-value">{{ app.lastTestAt ? formatDate(app.lastTestAt) : 'Never' }}</span>
          </div>
        </div>

        <div class="app-actions">
          <BaseButton label="Manage Tests" :icon="Settings" variant="secondary" size="sm" @click="viewApplicationDetail(app.id)" />
          <BaseButton label="Edit" :icon="Edit" variant="secondary" size="sm" @click="editApplication(app)" />
          <BaseButton label="History" :icon="History" variant="ghost" size="sm" @click="viewHistory(app.id)" />
          <BaseButton label="Test" :icon="TestTube" variant="ghost" size="sm" @click="testApplication(app)" />
          <BaseButton label="Delete" :icon="Trash2" variant="danger" size="sm" @click="deleteApplication(app.id)" />
        </div>
      </div>
    </div>

    <!-- Application Modal -->
    <BaseModal
      :isOpen="showCreateModal"
      :title="editingApp ? 'Edit Application' : 'Register Application'"
      :icon="Layers"
      @update:isOpen="showCreateModal = $event"
      @close="closeModal"
    >
      <BaseForm @submit="saveApplication" @cancel="closeModal">
        <div class="form-group">
          <label>Application Name *</label>
          <input
            v-model="appForm.name"
            type="text"
            required
            placeholder="e.g., Research Tracker API"
          />
        </div>
        <div class="form-group">
          <label>Application ID *</label>
          <input
            v-model="appForm.id"
            type="text"
            required
            placeholder="e.g., research-tracker-api"
            :disabled="!!editingApp"
          />
          <small>Unique identifier (cannot be changed after creation)</small>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Application Type *</label>
            <Dropdown
              v-model="appForm.type"
              :options="appTypeOptions"
              placeholder="Select type..."
            />
          </div>
          <div class="form-group">
            <label>Status</label>
            <Dropdown
              v-model="appForm.status"
              :options="statusOptions"
              placeholder="Select status..."
            />
          </div>
        </div>
        <div class="form-group">
          <label>Base URL</label>
          <input
            v-model="appForm.baseUrl"
            type="url"
            placeholder="https://api.example.com"
          />
        </div>
        <div class="form-group">
          <label>Team</label>
          <input
            v-model="appForm.team"
            type="text"
            placeholder="e.g., Platform Team"
          />
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea
            v-model="appForm.description"
            rows="3"
            placeholder="Brief description of the application..."
          ></textarea>
        </div>
        <template #footer>
          <BaseButton label="Cancel" variant="secondary" @click="closeModal" />
          <BaseButton 
            :label="editingApp ? 'Update' : 'Register' + ' Application'" 
            type="submit"
            :disabled="!isFormValid"
          />
        </template>
      </BaseForm>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Layers,
  Plus,
  Edit,
  Trash2,
  TestTube,
  History,
  Settings
} from 'lucide-vue-next';
import BaseButton from '../../components/BaseButton.vue';
import BaseModal from '../../components/BaseModal.vue';
import BaseForm from '../../components/BaseForm.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import EmptyState from '../../components/EmptyState.vue';
import Dropdown from '../../components/Dropdown.vue';
import axios from 'axios';

const router = useRouter();

const applications = ref<any[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showCreateModal = ref(false);
const editingApp = ref<any>(null);
const latestResults = ref<Record<string, any>>({});

const appForm = ref({
  name: '',
  id: '',
  type: 'api',
  status: 'active',
  baseUrl: '',
  team: '',
  description: '',
  configJson: '{}'
});

const appTypeOptions = computed(() => [
  { label: 'API', value: 'api' },
  { label: 'Web Application', value: 'web' },
  { label: 'Mobile App', value: 'mobile' },
  { label: 'Service', value: 'service' }
]);

const statusOptions = computed(() => [
  { label: 'Active', value: 'active' },
  { label: 'Inactive', value: 'inactive' },
  { label: 'Deprecated', value: 'deprecated' }
]);

const isFormValid = computed(() => {
  return appForm.value.name.trim().length > 0 && appForm.value.id.trim().length > 0;
});

const loadApplications = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get("/api/v1/applications");
    applications.value = response.data.map((app: any) => ({
      ...app,
      registeredAt: new Date(app.registeredAt),
      lastTestAt: app.lastTestAt ? new Date(app.lastTestAt) : null,
      updatedAt: new Date(app.updatedAt)
    }));
    await loadLatestResults();
  } catch (err: any) {
    error.value = err.message || 'Failed to load applications';
    console.error('Error loading applications:', err);
  } finally {
    loading.value = false;
  }
};

const loadLatestResults = async () => {
  // Load latest test results for each application
  // Implementation would fetch from API
};

const getLatestResult = (appId: string) => {
  return latestResults.value[appId];
};

const formatDate = (date: Date): string => {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

const editApplication = (app: any) => {
  editingApp.value = app;
  appForm.value = {
    name: app.name,
    id: app.id,
    type: app.type,
    status: app.status,
    baseUrl: app.baseUrl || '',
    team: app.team || '',
    description: app.description || '',
    configJson: app.config ? JSON.stringify(app.config, null, 2) : '{}'
  };
  showCreateModal.value = true;
};

const viewHistory = (appId: string) => {
  router.push(`/tests?app=${appId}`);
};

const viewApplicationDetail = (appId: string) => {
  router.push(`/admin/applications/${appId}`);
};

const testApplication = async (app: any) => {
  try {
    await axios.post(`/api/v1/applications/${app.id}/run-tests`);
    await loadApplications();
    alert('Tests started successfully');
  } catch (err: any) {
    console.error('Error running tests:', err);
    alert(err.response?.data?.message || 'Failed to run tests');
  }
};

const deleteApplication = async (id: string) => {
  if (!confirm(`Are you sure you want to delete application "${id}"?`)) {
    return;
  }
  
  try {
    await axios.delete(`/api/v1/applications/${id}`);
    await loadApplications();
  } catch (err: any) {
    console.error('Error deleting application:', err);
    alert(err.response?.data?.message || 'Failed to delete application');
  }
};

const saveApplication = async () => {
  try {
    const config = appForm.value.configJson 
      ? JSON.parse(appForm.value.configJson)
      : {};

    const payload = {
      name: appForm.value.name,
      type: appForm.value.type,
      status: appForm.value.status,
      baseUrl: appForm.value.baseUrl || undefined,
      team: appForm.value.team || undefined,
      description: appForm.value.description || undefined,
      config: Object.keys(config).length > 0 ? config : undefined
    };

    if (editingApp.value) {
      await axios.patch(`/api/v1/applications/${editingApp.value.id}`, payload);
    } else {
      await axios.post("/api/v1/applications", {
        ...payload,
        id: appForm.value.id
      });
    }

    await loadApplications();
    closeModal();
  } catch (err: any) {
    console.error('Error saving application:', err);
    alert(err.response?.data?.message || 'Failed to save application');
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingApp.value = null;
  appForm.value = {
    name: '',
    id: '',
    type: 'api',
    status: 'active',
    baseUrl: '',
    team: '',
    description: '',
    configJson: '{}'
  };
};

onMounted(() => {
  loadApplications();
});
</script>

<style scoped>
.admin-applications-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.section-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.applications-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.application-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.app-header {
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.app-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-xs);
}

.app-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.app-status-badges {
  display: flex;
  gap: var(--spacing-xs);
  align-items: center;
}

.app-id {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: 0;
}

.app-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
}

.detail-item {
  display: flex;
  justify-content: space-between;
  font-size: var(--font-size-sm);
}

.detail-label {
  color: var(--color-text-secondary);
}

.detail-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.app-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.form-group small {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}
</style>
