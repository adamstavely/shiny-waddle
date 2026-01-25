<template>
  <div class="salesforce-experience-cloud-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Salesforce Experience Cloud Testing</h1>
          <p class="page-description">Test Salesforce Experience Cloud applications for security misconfigurations using aura-inspector</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Configuration
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading configurations...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error" class="configs-grid">
      <div
        v-for="config in configs"
        :key="config.id"
        class="config-card"
        @click="viewConfig(config.id)"
      >
        <div class="card-header">
          <div class="card-title-group">
            <Cloud class="card-icon" />
            <h3 class="card-title">{{ config.name }}</h3>
          </div>
          <div class="card-actions" @click.stop>
            <button @click.stop="editConfig(config)" class="icon-btn" title="Edit">
              <Edit class="icon" />
            </button>
            <button @click.stop="deleteConfig(config.id)" class="icon-btn danger" title="Delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>
        
        <div class="card-body">
          <div class="config-detail">
            <span class="detail-label">URL:</span>
            <span class="detail-value">{{ config.url }}</span>
          </div>
          <div v-if="config.app" class="config-detail">
            <span class="detail-label">App:</span>
            <span class="detail-value">{{ config.app }}</span>
          </div>
          <div v-if="config.objectList && config.objectList.length > 0" class="config-detail">
            <span class="detail-label">Objects:</span>
            <span class="detail-value">{{ config.objectList.join(', ') }}</span>
          </div>
          <div class="config-detail">
            <span class="detail-label">Created:</span>
            <span class="detail-value">{{ formatDate(config.createdAt) }}</span>
          </div>
        </div>

        <div class="card-footer">
          <button @click.stop="runTest(config.id)" class="btn-secondary" :disabled="runningTests[config.id]">
            <Play v-if="!runningTests[config.id]" class="btn-icon" />
            <div v-else class="loading-spinner-small"></div>
            {{ runningTests[config.id] ? 'Running...' : 'Run Test' }}
          </button>
          <button @click.stop="viewResults(config.id)" class="btn-secondary">
            <BarChart3 class="btn-icon" />
            View Results
          </button>
        </div>
      </div>

      <div v-if="configs.length === 0" class="empty-state">
        <Cloud class="empty-icon" />
        <p>No configurations found</p>
        <button @click="showCreateModal = true" class="btn-primary">
          Create Your First Configuration
        </button>
      </div>
    </div>

    <!-- Create/Edit Config Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal || editingConfig" class="modal-overlay" @click="closeModal">
          <div class="modal-content large-modal" @click.stop>
            <div class="modal-header">
              <h2>{{ editingConfig ? 'Edit Configuration' : 'Create Configuration' }}</h2>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            
            <div class="modal-body">
              <form @submit.prevent="saveConfig" class="config-form">
                <div class="form-group">
                  <label>Name <span class="required">*</span></label>
                  <input v-model="formData.name" type="text" required class="form-input" placeholder="Production Site Audit" />
                </div>

                <div class="form-group">
                  <label>URL <span class="required">*</span></label>
                  <input v-model="formData.url" type="url" required class="form-input" placeholder="https://example.force.com" />
                </div>

                <div class="form-group">
                  <label>Cookies (for authenticated access)</label>
                  <textarea v-model="formData.cookies" class="form-input" rows="2" placeholder="sid=...;"></textarea>
                </div>

                <div class="form-row">
                  <div class="form-group">
                    <label>App Path</label>
                    <input v-model="formData.app" type="text" class="form-input" placeholder="/myApp" />
                  </div>

                  <div class="form-group">
                    <label>Aura Path</label>
                    <input v-model="formData.aura" type="text" class="form-input" placeholder="/aura" />
                  </div>
                </div>

                <div class="form-group">
                  <label>Object List (comma-separated)</label>
                  <input v-model="objectListInput" type="text" class="form-input" placeholder="Account, Contact, Lead" />
                  <small class="form-hint">Leave empty to test all objects</small>
                </div>

                <div class="form-row">
                  <div class="form-group">
                    <label>Timeout (ms)</label>
                    <input v-model.number="formData.timeout" type="number" class="form-input" placeholder="300000" />
                  </div>

                  <div class="form-group">
                    <label>Python Path</label>
                    <input v-model="formData.pythonPath" type="text" class="form-input" placeholder="python3" />
                  </div>
                </div>

                <div class="form-group">
                  <label>
                    <input v-model="formData.noGraphQL" type="checkbox" />
                    Disable GraphQL checks
                  </label>
                </div>

                <div class="form-group">
                  <label>
                    <input v-model="formData.insecure" type="checkbox" />
                    Ignore TLS certificate validation
                  </label>
                </div>

                <div class="form-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">Cancel</button>
                  <button type="submit" class="btn-primary" :disabled="saving">
                    {{ saving ? 'Saving...' : (editingConfig ? 'Update' : 'Create') }}
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
import { useRouter } from 'vue-router';
import { Teleport, Transition } from 'vue';
import { Plus, Edit, Trash2, Play, BarChart3, Cloud, X } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import { useSalesforceExperienceCloud } from '../../composables/useSalesforceExperienceCloud';
import type { SalesforceExperienceCloudConfigEntity } from '../../types/salesforce-experience-cloud';

const router = useRouter();
const { loading, error, getConfigs, createConfig, updateConfig, deleteConfig: deleteConfigApi } = useSalesforceExperienceCloud();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
];

const configs = ref<SalesforceExperienceCloudConfigEntity[]>([]);
const showCreateModal = ref(false);
const editingConfig = ref<SalesforceExperienceCloudConfigEntity | null>(null);
const saving = ref(false);
const runningTests = ref<Record<string, boolean>>({});

const objectListInput = ref('');
const formData = ref({
  name: '',
  url: '',
  cookies: '',
  app: '',
  aura: '',
  objectList: [] as string[],
  timeout: 300000,
  pythonPath: '',
  noGraphQL: false,
  insecure: false,
});

const loadConfigs = async () => {
  try {
    configs.value = await getConfigs();
  } catch (err) {
    console.error('Failed to load configurations:', err);
  }
};

const saveConfig = async () => {
  saving.value = true;
  try {
    const configToSave = {
      ...formData.value,
      objectList: objectListInput.value ? objectListInput.value.split(',').map(s => s.trim()).filter(Boolean) : undefined,
    };

    if (editingConfig.value) {
      await updateConfig(editingConfig.value.id, configToSave);
    } else {
      await createConfig(configToSave);
    }

    await loadConfigs();
    closeModal();
  } catch (err) {
    console.error('Failed to save configuration:', err);
  } finally {
    saving.value = false;
  }
};

const editConfig = (config: SalesforceExperienceCloudConfigEntity) => {
  editingConfig.value = config;
  formData.value = {
    name: config.name,
    url: config.url,
    cookies: config.cookies || '',
    app: config.app || '',
    aura: config.aura || '',
    objectList: config.objectList || [],
    timeout: config.timeout || 300000,
    pythonPath: config.pythonPath || '',
    noGraphQL: config.noGraphQL || false,
    insecure: config.insecure || false,
  };
  objectListInput.value = config.objectList?.join(', ') || '';
  showCreateModal.value = true;
};

const deleteConfig = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration?')) return;
  
  try {
    await deleteConfigApi(id);
    await loadConfigs();
  } catch (err) {
    console.error('Failed to delete configuration:', err);
  }
};

const runTest = (configId: string) => {
  router.push(`/salesforce-experience-cloud/test-runner/${configId}`);
};

const viewConfig = (id: string) => {
  router.push(`/salesforce-experience-cloud/config/${id}`);
};

const viewResults = (id: string) => {
  router.push(`/salesforce-experience-cloud/results?configId=${id}`);
};

const closeModal = () => {
  showCreateModal.value = false;
  editingConfig.value = null;
  formData.value = {
    name: '',
    url: '',
    cookies: '',
    app: '',
    aura: '',
    objectList: [],
    timeout: 300000,
    pythonPath: '',
    noGraphQL: false,
    insecure: false,
  };
  objectListInput.value = '';
};

const formatDate = (date: Date | string) => {
  return new Date(date).toLocaleDateString();
};

onMounted(() => {
  loadConfigs();
});
</script>

<style scoped>
.salesforce-experience-cloud-page {
  padding: 2rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  width: 100%;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.page-description {
  color: #666;
  margin-bottom: 0;
}

.configs-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 1.5rem;
}

.config-card {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.config-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  transform: translateY(-2px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.card-title-group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.card-icon {
  width: 24px;
  height: 24px;
  color: #6366f1;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
}

.card-actions {
  display: flex;
  gap: 0.5rem;
}

.icon-btn {
  background: none;
  border: none;
  padding: 0.25rem;
  cursor: pointer;
  color: #666;
  transition: color 0.2s;
}

.icon-btn:hover {
  color: #333;
}

.icon-btn.danger:hover {
  color: #ef4444;
}

.icon {
  width: 18px;
  height: 18px;
}

.card-body {
  margin-bottom: 1rem;
}

.config-detail {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  font-size: 0.9rem;
}

.detail-label {
  font-weight: 500;
  color: #666;
}

.detail-value {
  color: #333;
  word-break: break-all;
}

.card-footer {
  display: flex;
  gap: 0.5rem;
  padding-top: 1rem;
  border-top: 1px solid #e0e0e0;
}

.empty-state {
  grid-column: 1 / -1;
  text-align: center;
  padding: 4rem 2rem;
  color: #666;
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 1rem;
  color: #ccc;
}

.config-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.form-group label {
  font-weight: 500;
  font-size: 0.9rem;
}

.required {
  color: #ef4444;
}

.form-input {
  padding: 0.5rem;
  border: 1px solid #ddd;
  border-radius: 4px;
  font-size: 0.9rem;
}

.form-hint {
  color: #666;
  font-size: 0.85rem;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  margin-top: 1rem;
}

.btn-primary,
.btn-secondary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  border-radius: 4px;
  border: none;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-primary {
  background: #6366f1;
  color: white;
}

.btn-primary:hover:not(:disabled) {
  background: #4f46e5;
}

.btn-secondary {
  background: #f3f4f6;
  color: #333;
}

.btn-secondary:hover:not(:disabled) {
  background: #e5e7eb;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.loading-spinner-small {
  width: 18px;
  height: 18px;
  border: 2px solid #f3f4f6;
  border-top-color: #6366f1;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
