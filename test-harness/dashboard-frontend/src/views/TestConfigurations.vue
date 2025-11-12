<template>
  <div class="test-configurations-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Configurations</h1>
          <p class="page-description">Manage test parameters and logic configurations for all test types</p>
        </div>
        <div class="header-actions">
          <button @click="showCreateModal = true" class="btn-primary">
            <Plus class="btn-icon" />
            Create Configuration
          </button>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters-section">
      <div class="filter-group">
        <label>Type</label>
        <select v-model="filterType" @change="loadConfigurations">
          <option value="">All Types</option>
          <option value="rls-cls">RLS/CLS</option>
          <option value="network-policy">Network Policy</option>
          <option value="dlp">DLP</option>
          <option value="identity-lifecycle">Identity Lifecycle</option>
          <option value="api-gateway">API Gateway</option>
        </select>
      </div>
      <div class="filter-group">
        <label>Search</label>
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search configurations..."
          @input="loadConfigurations"
        />
      </div>
    </div>

    <!-- Configurations List -->
    <div v-if="loading" class="loading">Loading configurations...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else class="configurations-list">
      <div
        v-for="config in filteredConfigurations"
        :key="config.id"
        class="configuration-card"
      >
        <div class="card-header">
          <div class="card-title-section">
            <h3 class="card-title">{{ config.name }}</h3>
            <span class="config-type-badge" :class="`type-${config.type}`">
              {{ getTypeLabel(config.type) }}
            </span>
          </div>
          <div class="card-actions">
            <button @click="editConfiguration(config)" class="btn-icon" title="Edit">
              <Edit class="icon" />
            </button>
            <button @click="duplicateConfiguration(config)" class="btn-icon" title="Duplicate">
              <Copy class="icon" />
            </button>
            <button @click="testConfiguration(config)" class="btn-icon" title="Test">
              <Play class="icon" />
            </button>
            <button @click="deleteConfiguration(config.id)" class="btn-icon btn-danger" title="Delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>
        <div class="card-body">
          <p class="card-description">{{ config.description || 'No description' }}</p>
          <div class="card-meta">
            <span class="meta-item">
              <Calendar class="meta-icon" />
              Created: {{ formatDate(config.createdAt) }}
            </span>
            <span class="meta-item">
              <Calendar class="meta-icon" />
              Updated: {{ formatDate(config.updatedAt) }}
            </span>
          </div>
        </div>
      </div>
      <div v-if="filteredConfigurations.length === 0" class="empty-state">
        <Settings class="empty-icon" />
        <p>No configurations found</p>
        <button @click="showCreateModal = true" class="btn-primary">
          Create your first configuration
        </button>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <ConfigurationModal
      :show="showCreateModal || editingConfig !== null"
      :config="editingConfig"
      :type="selectedType"
      @close="closeModal"
      @save="saveConfiguration"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Plus, Edit, Trash2, Play, Copy, Calendar, Settings } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import ConfigurationModal from '../components/configurations/ConfigurationModal.vue';
import axios from 'axios';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Test Configurations' }
];

interface TestConfiguration {
  id: string;
  name: string;
  type: 'rls-cls' | 'network-policy' | 'dlp' | 'identity-lifecycle' | 'api-gateway';
  description?: string;
  createdAt: string;
  updatedAt: string;
  [key: string]: any;
}

const loading = ref(false);
const error = ref<string | null>(null);
const configurations = ref<TestConfiguration[]>([]);
const filterType = ref('');
const searchQuery = ref('');
const showCreateModal = ref(false);
const editingConfig = ref<TestConfiguration | null>(null);
const selectedType = ref<string>('');

const filteredConfigurations = computed(() => {
  let filtered = configurations.value;

  if (filterType.value) {
    filtered = filtered.filter(c => c.type === filterType.value);
  }

  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase();
    filtered = filtered.filter(c =>
      c.name.toLowerCase().includes(query) ||
      (c.description && c.description.toLowerCase().includes(query))
    );
  }

  return filtered;
});

const getTypeLabel = (type: string) => {
  const labels: Record<string, string> = {
    'rls-cls': 'RLS/CLS',
    'network-policy': 'Network Policy',
    'dlp': 'DLP',
    'identity-lifecycle': 'Identity Lifecycle',
    'api-gateway': 'API Gateway'
  };
  return labels[type] || type;
};

const formatDate = (dateString: string) => {
  return new Date(dateString).toLocaleDateString();
};

const loadConfigurations = async () => {
  loading.value = true;
  error.value = null;
  try {
    const url = filterType.value
      ? `/api/test-configurations?type=${filterType.value}`
      : '/api/test-configurations';
    const response = await axios.get(url);
    configurations.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load configurations';
    console.error('Error loading configurations:', err);
  } finally {
    loading.value = false;
  }
};

const editConfiguration = (config: TestConfiguration) => {
  editingConfig.value = config;
  selectedType.value = config.type;
  showCreateModal.value = true;
};

const duplicateConfiguration = async (config: TestConfiguration) => {
  try {
    const response = await axios.post(`/api/test-configurations/${config.id}/duplicate`);
    await loadConfigurations();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to duplicate configuration';
    console.error('Error duplicating configuration:', err);
  }
};

const testConfiguration = async (config: TestConfiguration) => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.post(`/api/test-configurations/${config.id}/test`);
    
    // Format test results for display
    let resultMessage = `Test completed for: ${config.name}\n\n`;
    
    // Display basic test results
    if (response.data.passed !== undefined) {
      resultMessage += `Status: ${response.data.passed ? 'PASSED' : 'FAILED'}\n`;
    }
    
    // Display coverage results for RLS/CLS
    if (response.data.coveragePercentage !== undefined) {
      resultMessage += `Coverage: ${response.data.coveragePercentage.toFixed(2)}%\n`;
      if (response.data.validationResults) {
        resultMessage += `Min Coverage Required: ${response.data.validationResults.minRLSCoverage || response.data.validationResults.minCLSCoverage || 'N/A'}%\n`;
        resultMessage += `Coverage Met: ${response.data.validationResults.minRLSCoverageMet || response.data.validationResults.minCLSCoverageMet ? 'Yes' : 'No'}\n`;
      }
    }
    
    // Display workflow validation for Identity Lifecycle
    if (response.data.workflowValidation) {
      resultMessage += `\nWorkflow Validation:\n`;
      resultMessage += `  Required Steps: ${response.data.workflowValidation.requiredSteps?.join(', ') || 'N/A'}\n`;
      resultMessage += `  Completed Steps: ${response.data.workflowValidation.completedSteps?.join(', ') || 'N/A'}\n`;
      resultMessage += `  All Required Completed: ${response.data.workflowValidation.allRequiredStepsCompleted ? 'Yes' : 'No'}\n`;
      if (response.data.workflowValidation.missingSteps?.length > 0) {
        resultMessage += `  Missing Steps: ${response.data.workflowValidation.missingSteps.join(', ')}\n`;
      }
    }
    
    // Display custom validation results
    if (response.data.customValidationResults && response.data.customValidationResults.length > 0) {
      resultMessage += `\nCustom Validations:\n`;
      response.data.customValidationResults.forEach((val: any) => {
        resultMessage += `  ${val.name}: ${val.passed ? 'PASSED' : 'FAILED'}\n`;
        if (val.description) {
          resultMessage += `    ${val.description}\n`;
        }
      });
    }
    
    // Display custom check results
    if (response.data.customCheckResults && response.data.customCheckResults.length > 0) {
      resultMessage += `\nCustom Checks:\n`;
      response.data.customCheckResults.forEach((check: any) => {
        resultMessage += `  ${check.name}: ${check.passed ? 'PASSED' : 'FAILED'}\n`;
        if (check.description) {
          resultMessage += `    ${check.description}\n`;
        }
      });
    }
    
    // Display custom rule results
    if (response.data.customRuleResults && response.data.customRuleResults.length > 0) {
      resultMessage += `\nCustom Rules:\n`;
      response.data.customRuleResults.forEach((rule: any) => {
        resultMessage += `  ${rule.source} -> ${rule.target}: ${rule.passed ? 'PASSED' : 'FAILED'}\n`;
        if (rule.description) {
          resultMessage += `    ${rule.description}\n`;
        }
      });
    }
    
    // If result is too complex, show JSON
    if (resultMessage.length > 500 || !response.data.passed && response.data.coveragePercentage === undefined) {
      resultMessage += `\n\nFull Results:\n${JSON.stringify(response.data, null, 2)}`;
    }
    
    alert(resultMessage);
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to test configuration';
    alert(`Error testing configuration: ${error.value}`);
    console.error('Error testing configuration:', err);
  } finally {
    loading.value = false;
  }
};

const deleteConfiguration = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration?')) {
    return;
  }
  try {
    await axios.delete(`/api/test-configurations/${id}`);
    await loadConfigurations();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete configuration';
    console.error('Error deleting configuration:', err);
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingConfig.value = null;
  selectedType.value = '';
};

const saveConfiguration = async (configData: any) => {
  try {
    if (editingConfig.value) {
      await axios.put(`/api/test-configurations/${editingConfig.value.id}`, configData);
    } else {
      await axios.post('/api/test-configurations', configData);
    }
    await loadConfigurations();
    closeModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to save configuration';
    console.error('Error saving configuration:', err);
  }
};

onMounted(() => {
  loadConfigurations();
});
</script>

<style scoped>
.test-configurations-page {
  width: 100%;
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
  flex-wrap: wrap;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  color: #a0aec0;
  font-size: 1.1rem;
}

.header-actions {
  display: flex;
  gap: 1rem;
}

.filters-section {
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
  padding: 1.5rem;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.filter-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.filter-group label {
  font-weight: 500;
  font-size: 0.875rem;
  color: #a0aec0;
}

.filter-group select,
.filter-group input {
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
  transition: all 0.2s;
}

.filter-group select:focus,
.filter-group input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-group select option {
  background: #1a1f2e;
  color: #ffffff;
}

.configurations-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 1.5rem;
}

.configuration-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.3s;
}

.configuration-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
  transform: translateY(-2px);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.card-title-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.config-type-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.type-rls-cls {
  background: rgba(25, 118, 210, 0.2);
  color: #64b5f6;
  border: 1px solid rgba(25, 118, 210, 0.3);
}

.type-network-policy {
  background: rgba(123, 31, 162, 0.2);
  color: #ba68c8;
  border: 1px solid rgba(123, 31, 162, 0.3);
}

.type-dlp {
  background: rgba(230, 81, 0, 0.2);
  color: #ffb74d;
  border: 1px solid rgba(230, 81, 0, 0.3);
}

.type-identity-lifecycle {
  background: rgba(56, 142, 60, 0.2);
  color: #81c784;
  border: 1px solid rgba(56, 142, 60, 0.3);
}

.type-api-gateway {
  background: rgba(194, 24, 91, 0.2);
  color: #f48fb1;
  border: 1px solid rgba(194, 24, 91, 0.3);
}

.card-actions {
  display: flex;
  gap: 0.5rem;
}

.btn-icon {
  padding: 0.5rem;
  border: none;
  background: transparent;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
  color: #a0aec0;
  display: flex;
  align-items: center;
  justify-content: center;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.btn-icon.btn-danger:hover {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.btn-icon .icon {
  width: 1rem;
  height: 1rem;
}

.card-body {
  margin-top: 1rem;
}

.card-description {
  color: #a0aec0;
  margin-bottom: 1rem;
  font-size: 0.9rem;
  line-height: 1.5;
}

.card-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.875rem;
  color: #718096;
}

.meta-item {
  display: flex;
  align-items: center;
  gap: 0.25rem;
}

.meta-icon {
  width: 0.875rem;
  height: 0.875rem;
  color: #718096;
}

.empty-state {
  grid-column: 1 / -1;
  text-align: center;
  padding: 4rem 2rem;
  color: #a0aec0;
}

.empty-icon {
  width: 4rem;
  height: 4rem;
  margin: 0 auto 1rem;
  opacity: 0.5;
  color: #718096;
}

.loading,
.error {
  text-align: center;
  padding: 2rem;
  color: #a0aec0;
}

.error {
  color: #fc8181;
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  font-weight: 600;
  transition: all 0.2s;
  font-size: 0.9rem;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon {
  width: 1.25rem;
  height: 1.25rem;
}
</style>

