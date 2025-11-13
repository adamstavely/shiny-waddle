<template>
  <div class="test-type-card" :class="{ expanded: isExpanded }">
    <div class="card-header" @click="toggleExpand">
      <div class="card-title-section">
        <component :is="icon" class="card-icon" />
        <div class="card-title-group">
          <h3 class="card-title">{{ name }}</h3>
          <p class="card-description">{{ description }}</p>
        </div>
      </div>
      <div class="card-stats">
        <div class="stat-item">
          <span class="stat-label">Configs</span>
          <span class="stat-value">{{ configCount }}</span>
        </div>
        <div class="stat-item" v-if="lastRunStatus || lastRunStatusProp">
          <span class="stat-label">Last Run</span>
          <span class="stat-value" :class="`status-${lastRunStatus || lastRunStatusProp}`">
            {{ lastRunStatus || lastRunStatusProp }}
          </span>
        </div>
      </div>
      <ChevronDown class="expand-icon" :class="{ rotated: isExpanded }" />
    </div>

    <div v-if="isExpanded" class="card-content">
      <!-- Configuration Selector -->
      <div class="config-section">
        <div class="section-header">
          <Settings class="section-icon" />
          <h4>Configurations</h4>
          <button @click.stop="showCreateConfig = true" class="btn-small">
            <Plus class="btn-icon-small" />
            New
          </button>
        </div>
        <div v-if="configurations.length === 0" class="empty-configs">
          <p>No configurations yet. Create one to get started.</p>
        </div>
        <div v-else class="configs-list">
          <div
            v-for="config in configurations"
            :key="config.id"
            class="config-item"
            :class="{ active: selectedConfigId === config.id }"
            @click.stop="selectConfig(config.id)"
          >
            <div class="config-info">
              <span class="config-name">{{ config.name }}</span>
              <span class="config-status" :class="config.enabled ? 'enabled' : 'disabled'">
                {{ config.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </div>
            <div class="config-actions">
              <button @click.stop="editConfig(config)" class="icon-btn" title="Edit">
                <Edit class="icon-small" />
              </button>
              <button @click.stop="deleteConfig(config.id)" class="icon-btn danger" title="Delete">
                <Trash2 class="icon-small" />
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Test Functions -->
      <div class="test-functions-section">
        <div class="section-header">
          <Play class="section-icon" />
          <h4>Test Functions</h4>
        </div>
        <div class="functions-list">
          <div
            v-for="testFunc in availableTestFunctions"
            :key="testFunc.id"
            class="test-function-card"
          >
            <div class="function-header">
              <component :is="testFunc.icon" class="function-icon" />
              <div class="function-info">
                <h5 class="function-name">{{ testFunc.name }}</h5>
                <p class="function-description">{{ testFunc.description }}</p>
              </div>
            </div>
            <div class="function-actions">
              <Dropdown
                v-model="selectedConfigId"
                :options="configOptions"
                placeholder="Select config..."
                class="config-selector-small"
                v-if="configurations.length > 0"
              />
              <button
                @click="runTestFunction(testFunc)"
                class="btn-run-function"
                :disabled="running || (configurations.length > 0 && !selectedConfigId)"
              >
                <Play v-if="!running || currentTestFunction?.id !== testFunc.id" class="btn-icon-small" />
                <div v-else class="spinner-small"></div>
                {{ running && currentTestFunction?.id === testFunc.id ? 'Running...' : 'Run' }}
              </button>
            </div>
            <div v-if="testResults[testFunc.id]" class="function-result">
              <div class="result-status" :class="testResults[testFunc.id].passed !== false ? 'passed' : 'failed'">
                <CheckCircle2 v-if="testResults[testFunc.id].passed !== false" class="result-icon-small" />
                <XCircle v-else class="result-icon-small" />
                <span>{{ testResults[testFunc.id].passed !== false ? 'Passed' : 'Failed' }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Recent Results -->
      <div v-if="recentResults.length > 0" class="results-section">
        <div class="section-header">
          <FileText class="section-icon" />
          <h4>Recent Results</h4>
        </div>
        <div class="results-list">
          <div
            v-for="result in recentResults"
            :key="result.id"
            class="result-item"
            @click="viewResult(result)"
          >
            <span class="result-name">{{ result.testName }}</span>
            <span class="result-status" :class="result.passed ? 'passed' : 'failed'">
              {{ result.passed ? 'Passed' : 'Failed' }}
            </span>
            <span class="result-time">{{ formatTime(result.timestamp) }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Config Modal -->
    <ConfigurationModal
      v-if="showCreateConfig"
      :show="showCreateConfig"
      :type="type"
      @close="showCreateConfig = false"
      @save="handleCreateConfig"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute } from 'vue-router';
import {
  ChevronDown,
  Settings,
  Plus,
  Edit,
  Trash2,
  Play,
  CheckCircle2,
  XCircle,
  FileText,
  Server,
  Shield,
  Zap,
  Lock,
  FileX,
  Network,
  AlertTriangle
} from 'lucide-vue-next';
import Dropdown from './Dropdown.vue';
import ConfigurationModal from './configurations/ConfigurationModal.vue';
import axios from 'axios';

interface Props {
  name: string;
  type: string;
  description: string;
  icon: any;
  configCount?: number;
  lastRunStatus?: string;
}

const props = defineProps<Props>();
const route = useRoute();

const isExpanded = ref(false);
const configurations = ref<any[]>([]);
const selectedConfigId = ref<string>('');
const running = ref(false);
const lastResult = ref<any>(null);
const recentResults = ref<any[]>([]);
const showCreateConfig = ref(false);
const loading = ref(false);
const lastRunStatus = ref<string | undefined>(undefined);
const lastRunTimestamp = ref<Date | undefined>(undefined);
const currentTestFunction = ref<any>(null);
const testResults = ref<Record<string, any>>({});

// Define available test functions for each test type
const availableTestFunctions = computed(() => {
  const functions: Record<string, any[]> = {
    'api-gateway': [
      { id: 'policy', name: 'Gateway Policy', description: 'Test API gateway access policies and rules', icon: Shield, endpoint: '/api/api-gateway/test-gateway-policy' },
      { id: 'rate-limit', name: 'Rate Limiting', description: 'Test rate limiting enforcement and thresholds', icon: Zap, endpoint: '/api/api-gateway/test-rate-limiting' },
      { id: 'service-auth', name: 'Service Auth', description: 'Test service-to-service authentication', icon: Lock, endpoint: '/api/api-gateway/test-service-auth' },
    ],
    'dlp': [
      { id: 'exfiltration', name: 'Exfiltration Detection', description: 'Detect unauthorized data exfiltration attempts', icon: FileX, endpoint: '/api/dlp/test-exfiltration' },
      { id: 'api-validation', name: 'API Response Validation', description: 'Validate API responses don\'t leak sensitive data', icon: Shield, endpoint: '/api/dlp/validate-api-response' },
      { id: 'bulk-export', name: 'Bulk Export Controls', description: 'Test bulk export restrictions and limits', icon: FileX, endpoint: '/api/dlp/test-bulk-export' },
    ],
    'network-policy': [
      { id: 'firewall', name: 'Firewall Rules', description: 'Test firewall rule configuration and enforcement', icon: Network, endpoint: '/api/network-policy/test-firewall-rules' },
      { id: 'service-to-service', name: 'Service-to-Service', description: 'Test service-to-service traffic policies', icon: Network, endpoint: '/api/network-policy/test-service-to-service' },
      { id: 'segmentation', name: 'Network Segmentation', description: 'Validate network segmentation policies', icon: Shield, endpoint: '/api/network-policy/validate-segmentation' },
    ],
    'api-security': [
      { id: 'full-suite', name: 'Full Security Suite', description: 'Run comprehensive API security tests', icon: Shield, endpoint: '/api/api-security/tests' },
    ],
  };
  
  return functions[props.type] || [{ id: 'default', name: 'Run Test', description: 'Run test with selected configuration', icon: Play, endpoint: `/api/test-configurations/${selectedConfigId.value}/test` }];
});

const configOptions = computed(() => {
  return [
    { label: 'Select configuration...', value: '' },
    ...configurations.value.map(c => ({
      label: c.name,
      value: c.id
    }))
  ];
});

const toggleExpand = async () => {
  isExpanded.value = !isExpanded.value;
  if (isExpanded.value && configurations.value.length === 0) {
    await loadConfigurations();
  }
};

const loadConfigurations = async () => {
  loading.value = true;
  try {
    const response = await axios.get(`/api/test-configurations?type=${props.type}`);
    configurations.value = response.data || [];
    // Load last run status for this test type
    await loadLastRunStatus();
  } catch (err) {
    console.error('Error loading configurations:', err);
    configurations.value = [];
  } finally {
    loading.value = false;
  }
};

const loadLastRunStatus = async () => {
  try {
    // Get all configurations of this type
    const configIds = configurations.value.map(c => c.id);
    if (configIds.length === 0) {
      lastRunStatus.value = undefined;
      return;
    }

    // Get the most recent test result for any configuration of this type
    const resultsPromises = configIds.map(async (configId) => {
      try {
        const response = await axios.get(`/api/test-results/test-configuration/${configId}?limit=1`);
        return response.data && response.data.length > 0 ? response.data[0] : null;
      } catch (err) {
        return null;
      }
    });

    const results = await Promise.all(resultsPromises);
    const validResults = results.filter(r => r !== null);
    
    if (validResults.length > 0) {
      // Sort by timestamp and get the most recent
      validResults.sort((a, b) => {
        const timeA = new Date(a.timestamp).getTime();
        const timeB = new Date(b.timestamp).getTime();
        return timeB - timeA;
      });
      
      const mostRecent = validResults[0];
      lastRunStatus.value = mostRecent.status === 'passed' ? 'passed' : 'failed';
      lastRunTimestamp.value = new Date(mostRecent.timestamp);
    } else {
      lastRunStatus.value = undefined;
    }
  } catch (err) {
    console.error('Error loading last run status:', err);
    lastRunStatus.value = undefined;
  }
};

const selectConfig = (id: string) => {
  selectedConfigId.value = id;
};

const editConfig = (config: any) => {
  // Emit event to parent to handle editing
  emit('edit-config', config);
};

const deleteConfig = async (id: string) => {
  if (!confirm('Are you sure you want to delete this configuration?')) {
    return;
  }
  try {
    await axios.delete(`/api/test-configurations/${id}`);
    await loadConfigurations();
  } catch (err) {
    console.error('Error deleting configuration:', err);
    alert('Failed to delete configuration');
  }
};

const runTest = async () => {
  if (!selectedConfigId.value) return;
  
  running.value = true;
  lastResult.value = null;
  
  try {
    const response = await axios.post(`/api/test-configurations/${selectedConfigId.value}/test`);
    lastResult.value = response.data;
    await loadRecentResults();
    await loadLastRunStatus(); // Refresh last run status
  } catch (err: any) {
    lastResult.value = {
      passed: false,
      error: err.response?.data?.message || 'Test failed'
    };
  } finally {
    running.value = false;
  }
};

const runTestFunction = async (testFunc: any) => {
  running.value = true;
  currentTestFunction.value = testFunc;
  testResults.value[testFunc.id] = null;
  
  try {
    let payload: any = {};
    
    // Add configId if a configuration is selected
    if (selectedConfigId.value) {
      payload.configId = selectedConfigId.value;
    }
    
    // Add type-specific default payloads
    if (props.type === 'api-gateway') {
      if (testFunc.id === 'policy') {
        payload = { ...payload, policy: { id: 'test', name: 'Test Policy', endpoint: '/api/test', method: 'GET', rules: [] }, request: { endpoint: '/api/test', method: 'GET', headers: {}, user: {} } };
      } else if (testFunc.id === 'rate-limit') {
        payload = { ...payload, endpoint: '/api/test', requests: 150 };
      } else if (testFunc.id === 'service-auth') {
        payload = { ...payload, source: 'frontend', target: 'backend' };
      }
    } else if (props.type === 'dlp') {
      if (testFunc.id === 'exfiltration') {
        payload = { ...payload, user: { id: 'test-user', email: 'test@example.com', role: 'admin' }, dataOperation: { type: 'export', data: { sensitive: 'SSN: 123-45-6789' } } };
      } else if (testFunc.id === 'api-validation') {
        payload = { ...payload, apiResponse: {}, allowedFields: ['id', 'name'], piiFields: ['email', 'ssn'] };
      } else if (testFunc.id === 'bulk-export') {
        payload = { ...payload, user: { id: 'test-user', email: 'test@example.com', role: 'viewer' }, exportRequest: { type: 'csv', recordCount: 5000 } };
      }
    } else if (props.type === 'network-policy') {
      if (testFunc.id === 'firewall') {
        payload = { ...payload };
      } else if (testFunc.id === 'service-to-service') {
        payload = { ...payload, source: 'frontend', target: 'backend' };
      } else if (testFunc.id === 'segmentation') {
        payload = { ...payload };
      }
    }
    
    const response = await axios.post(testFunc.endpoint, payload);
    testResults.value[testFunc.id] = response.data;
    await loadRecentResults();
    await loadLastRunStatus();
  } catch (err: any) {
    testResults.value[testFunc.id] = {
      passed: false,
      error: err.response?.data?.message || 'Test failed'
    };
  } finally {
    running.value = false;
    currentTestFunction.value = null;
  }
};

const loadRecentResults = async () => {
  if (!selectedConfigId.value) return;
  
  try {
    const response = await axios.get(`/api/test-results/test-configuration/${selectedConfigId.value}?limit=5`);
    recentResults.value = response.data || [];
  } catch (err) {
    console.error('Error loading recent results:', err);
    recentResults.value = [];
  }
};

// Load recent results when config is selected
watch(selectedConfigId, (newId) => {
  if (newId) {
    loadRecentResults();
  }
});

const handleCreateConfig = async (configData: any) => {
  try {
    await axios.post('/api/test-configurations', {
      ...configData,
      type: props.type
    });
    showCreateConfig.value = false;
    await loadConfigurations();
    await loadLastRunStatus();
  } catch (err) {
    console.error('Error creating configuration:', err);
    alert('Failed to create configuration');
  }
};

const viewResult = (result: any) => {
  emit('view-result', result);
};

const formatTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};

const emit = defineEmits<{
  'edit-config': [config: any];
  'view-result': [result: any];
}>();

// Auto-expand if this is the type specified in query params
onMounted(() => {
  const queryType = route.query.type as string;
  if (queryType === props.type) {
    isExpanded.value = true;
    loadConfigurations();
  }
});

// Watch for route changes to auto-expand
watch(() => route.query.type, (newType) => {
  if (newType === props.type && !isExpanded.value) {
    isExpanded.value = true;
    if (configurations.value.length === 0) {
      loadConfigurations();
    }
  }
});

// Computed for lastRunStatusProp
const lastRunStatusProp = computed(() => props.lastRunStatus);
</script>

<style scoped>
.test-type-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  overflow: hidden;
  transition: all 0.3s;
}

.test-type-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 24px;
  cursor: pointer;
  gap: 16px;
}

.card-title-section {
  display: flex;
  align-items: center;
  gap: 16px;
  flex: 1;
}

.card-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
  flex-shrink: 0;
}

.card-title-group {
  flex: 1;
}

.card-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.card-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.card-stats {
  display: flex;
  gap: 24px;
  align-items: center;
}

.stat-item {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.stat-label {
  font-size: 0.75rem;
  color: #718096;
}

.stat-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.stat-value.status-passed {
  color: #22c55e;
}

.stat-value.status-failed {
  color: #fc8181;
}

.expand-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  transition: transform 0.3s;
  flex-shrink: 0;
}

.expand-icon.rotated {
  transform: rotate(180deg);
}

.card-content {
  padding: 0 24px 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
  margin-top: 16px;
  padding-top: 24px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.section-header h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.section-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
}

.btn-small {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.empty-configs {
  padding: 16px;
  text-align: center;
  color: #718096;
  font-size: 0.875rem;
}

.configs-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.config-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.config-item:hover {
  background: rgba(15, 20, 25, 0.6);
  border-color: rgba(79, 172, 254, 0.4);
}

.config-item.active {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.config-info {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.config-name {
  font-weight: 500;
  color: #ffffff;
}

.config-status {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.config-status.enabled {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.config-status.disabled {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.config-actions {
  display: flex;
  gap: 8px;
}

.icon-btn {
  padding: 6px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.icon-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.icon-btn.danger {
  color: #fc8181;
  border-color: rgba(252, 129, 129, 0.2);
}

.icon-btn.danger:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.4);
}

.icon-small {
  width: 14px;
  height: 14px;
}

.test-functions-section {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.functions-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.test-function-card {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.15);
  border-radius: 8px;
  padding: 16px;
  transition: all 0.2s;
}

.test-function-card:hover {
  border-color: rgba(79, 172, 254, 0.3);
  background: rgba(15, 20, 25, 0.6);
}

.function-header {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 12px;
}

.function-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 2px;
}

.function-info {
  flex: 1;
}

.function-name {
  font-size: 0.95rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.function-description {
  font-size: 0.8rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.4;
}

.function-actions {
  display: flex;
  align-items: center;
  gap: 8px;
}

.config-selector-small {
  flex: 1;
  min-width: 150px;
}

.btn-run-function {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}

.btn-run-function:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-run-function:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon-small {
  width: 14px;
  height: 14px;
}

.function-result {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.result-icon-small {
  width: 16px;
  height: 16px;
}

.runner-controls {
  display: flex;
  gap: 12px;
  align-items: center;
}

.config-selector {
  flex: 1;
}

.btn-run {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  border-radius: 8px;
  color: #0f1419;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-run:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-run:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.spinner-small {
  width: 16px;
  height: 16px;
  border: 2px solid rgba(15, 20, 25, 0.3);
  border-top-color: #0f1419;
  border-radius: 50%;
  animation: spin 0.6s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.test-result {
  margin-top: 12px;
  padding: 12px;
  border-radius: 8px;
}

.result-status {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
}

.result-status.passed {
  color: #22c55e;
}

.result-status.failed {
  color: #fc8181;
}

.result-icon {
  width: 18px;
  height: 18px;
}

.result-error {
  margin-top: 8px;
  padding: 8px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 4px;
  color: #fc8181;
  font-size: 0.875rem;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.result-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.2s;
}

.result-item:hover {
  background: rgba(15, 20, 25, 0.6);
}

.result-name {
  flex: 1;
  color: #ffffff;
  font-size: 0.875rem;
}

.result-status {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.result-status.passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.result-status.failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.result-time {
  color: #718096;
  font-size: 0.75rem;
}
</style>


