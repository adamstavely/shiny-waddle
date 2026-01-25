<template>
  <div class="config-detail-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <div v-if="loading" class="loading">Loading configuration...</div>
    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="!loading && !error && config" class="config-detail-content">
      <div class="page-header">
        <div class="header-content">
          <div>
            <h1 class="page-title">{{ config.name }}</h1>
            <p class="page-description">{{ config.url }}</p>
          </div>
          <div class="header-actions">
            <button @click="editConfig" class="btn-secondary">
              <Edit class="btn-icon" />
              Edit
            </button>
            <button @click="runTest" class="btn-primary">
              <Play class="btn-icon" />
              Run Test
            </button>
          </div>
        </div>
      </div>

      <div class="config-details-grid">
        <div class="detail-section">
          <h2 class="section-title">Configuration Details</h2>
          <div class="detail-list">
            <div class="detail-item">
              <span class="detail-label">Name:</span>
              <span class="detail-value">{{ config.name }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">URL:</span>
              <span class="detail-value">{{ config.url }}</span>
            </div>
            <div v-if="config.app" class="detail-item">
              <span class="detail-label">App Path:</span>
              <span class="detail-value">{{ config.app }}</span>
            </div>
            <div v-if="config.aura" class="detail-item">
              <span class="detail-label">Aura Path:</span>
              <span class="detail-value">{{ config.aura }}</span>
            </div>
            <div v-if="config.objectList && config.objectList.length > 0" class="detail-item">
              <span class="detail-label">Object List:</span>
              <span class="detail-value">{{ config.objectList.join(', ') }}</span>
            </div>
            <div v-if="config.timeout" class="detail-item">
              <span class="detail-label">Timeout:</span>
              <span class="detail-value">{{ config.timeout }}ms</span>
            </div>
            <div v-if="config.pythonPath" class="detail-item">
              <span class="detail-label">Python Path:</span>
              <span class="detail-value">{{ config.pythonPath }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">GraphQL Checks:</span>
              <span class="detail-value">{{ config.noGraphQL ? 'Disabled' : 'Enabled' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">TLS Validation:</span>
              <span class="detail-value">{{ config.insecure ? 'Disabled' : 'Enabled' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Created:</span>
              <span class="detail-value">{{ formatDate(config.createdAt) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Updated:</span>
              <span class="detail-value">{{ formatDate(config.updatedAt) }}</span>
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h2 class="section-title">Quick Actions</h2>
          <div class="actions-list">
            <button @click="runTest" class="action-btn">
              <Play class="action-icon" />
              Run Full Audit
            </button>
            <button @click="viewResults" class="action-btn">
              <BarChart3 class="action-icon" />
              View All Results
            </button>
            <button @click="editConfig" class="action-btn">
              <Edit class="action-icon" />
              Edit Configuration
            </button>
            <button @click="deleteConfig" class="action-btn danger">
              <Trash2 class="action-icon" />
              Delete Configuration
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Edit, Play, BarChart3, Trash2 } from 'lucide-vue-next';
import Breadcrumb from '../../components/Breadcrumb.vue';
import { useSalesforceExperienceCloud } from '../../composables/useSalesforceExperienceCloud';
import type { SalesforceExperienceCloudConfigEntity } from '../../types/salesforce-experience-cloud';

const route = useRoute();
const router = useRouter();
const { loading, error, getConfig, deleteConfig: deleteConfigApi } = useSalesforceExperienceCloud();

const config = ref<SalesforceExperienceCloudConfigEntity | null>(null);
const configId = route.params.id as string;

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Salesforce Experience Cloud', to: '/salesforce-experience-cloud' },
  { label: config.value?.name || 'Configuration', to: '' },
];

const loadConfig = async () => {
  try {
    config.value = await getConfig(configId);
  } catch (err) {
    console.error('Failed to load configuration:', err);
  }
};

const editConfig = () => {
  router.push(`/salesforce-experience-cloud/config/${configId}/edit`);
};

const runTest = () => {
  router.push(`/salesforce-experience-cloud/test-runner/${configId}`);
};

const viewResults = () => {
  router.push(`/salesforce-experience-cloud/results?configId=${configId}`);
};

const deleteConfig = async () => {
  if (!confirm('Are you sure you want to delete this configuration?')) return;
  
  try {
    await deleteConfigApi(configId);
    router.push('/salesforce-experience-cloud');
  } catch (err) {
    console.error('Failed to delete configuration:', err);
  }
};

const formatDate = (date: Date | string) => {
  return new Date(date).toLocaleString();
};

onMounted(() => {
  loadConfig();
});
</script>

<style scoped>
.config-detail-page {
  padding: 2rem;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  margin-bottom: 0.5rem;
}

.page-description {
  color: #666;
}

.header-actions {
  display: flex;
  gap: 0.5rem;
}

.config-details-grid {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: 2rem;
}

.detail-section {
  background: white;
  border: 1px solid #e0e0e0;
  border-radius: 8px;
  padding: 1.5rem;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.detail-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.detail-item {
  display: flex;
  gap: 0.5rem;
}

.detail-label {
  font-weight: 500;
  color: #666;
  min-width: 150px;
}

.detail-value {
  color: #333;
  word-break: break-all;
}

.actions-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1rem;
  background: #f3f4f6;
  border: 1px solid #e0e0e0;
  border-radius: 4px;
  cursor: pointer;
  transition: all 0.2s;
  text-align: left;
}

.action-btn:hover {
  background: #e5e7eb;
}

.action-btn.danger {
  color: #ef4444;
}

.action-btn.danger:hover {
  background: #fee2e2;
}

.action-icon {
  width: 18px;
  height: 18px;
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

.btn-primary:hover {
  background: #4f46e5;
}

.btn-secondary {
  background: #f3f4f6;
  color: #333;
}

.btn-secondary:hover {
  background: #e5e7eb;
}

.btn-icon {
  width: 18px;
  height: 18px;
}
</style>
