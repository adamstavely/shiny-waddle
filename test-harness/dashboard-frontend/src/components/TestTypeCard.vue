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
          <span class="stat-label">Suites</span>
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
      <!-- Configuration section removed - infrastructure is now part of Application -->
      <div class="config-section">
        <div class="section-header">
          <Settings class="section-icon" />
          <h4>Infrastructure</h4>
        </div>
        <div class="empty-configs">
          <p>Infrastructure is now managed at the Application level. Go to Applications to configure infrastructure.</p>
          <button @click.stop="$router.push('/applications')" class="btn-small">
            View Applications
          </button>
        </div>
      </div>

      <!-- Test Functions -->
      <div class="test-functions-section">
        <div class="section-header">
          <Play class="section-icon" />
          <h4>Test Functions</h4>
        </div>
        <div class="info-banner">
          <AlertTriangle class="info-icon" />
          <p>Tests run automatically in CI/CD during builds. This UI is for viewing and managing test configurations only.</p>
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
  FileText,
  AlertTriangle
} from 'lucide-vue-next';
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
const recentResults = ref<any[]>([]);
const showCreateConfig = ref(false);
const loading = ref(false);
const lastRunStatus = ref<string | undefined>(undefined);
const lastRunTimestamp = ref<Date | undefined>(undefined);
const configUsage = ref<Record<string, { suites: Array<{ id: string; name: string }>; harnesses: Array<{ id: string; name: string }> }>>({});
const testSuites = ref<any[]>([]);
const testHarnesses = ref<any[]>([]);

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
    'data-pipeline': [
      { id: 'etl', name: 'ETL Pipeline', description: 'Test ETL pipeline access control and data transformations', icon: Server, endpoint: '/api/data-pipeline/configs/{configId}/test' },
      { id: 'streaming', name: 'Streaming Data', description: 'Test streaming data pipeline security', icon: Zap, endpoint: '/api/data-pipeline/configs/{configId}/test' },
    ],
  };
  
  return functions[props.type] || [];
});

// Configuration selector removed - no longer needed for test execution

const toggleExpand = async () => {
  isExpanded.value = !isExpanded.value;
  if (isExpanded.value && configurations.value.length === 0) {
    await loadConfigurations();
    await loadRecentResults();
    await loadUsageData();
  }
};

const loadConfigurations = async () => {
  // Test configurations have been moved to Application.infrastructure
  // This component should now show test suites or tests instead
  loading.value = true;
  try {
    // TODO: Update to load test suites or tests for this type instead
    configurations.value = [];
    await loadLastRunStatus();
  } catch (err) {
    console.error('Error loading data:', err);
    configurations.value = [];
  } finally {
    loading.value = false;
  }
};

const loadLastRunStatus = async () => {
  try {
    // TODO: Update to load test results for this test type from test suites
    // For now, return undefined since test configurations are gone
    lastRunStatus.value = undefined;
  } catch (err) {
    console.error('Error loading last run status:', err);
    lastRunStatus.value = undefined;
  }
};

// Config selection removed - no longer needed for test execution

const editConfig = (config: any) => {
  // Emit event to parent to handle editing
  emit('edit-config', config);
};

const deleteConfig = async (id: string) => {
  // Test configurations have been removed - this function is no longer needed
  console.warn('Test configurations have been removed. Use Application.infrastructure instead.');
};

// Test execution removed - tests run automatically in CI/CD during builds

const loadUsageData = async () => {
  try {
    // Load all test suites and harnesses
    const [suitesResponse, harnessesResponse] = await Promise.all([
      axios.get('/api/v1/test-suites'),
      axios.get('/api/v1/test-harnesses'),
    ]);
    
    testSuites.value = suitesResponse.data || [];
    testHarnesses.value = harnessesResponse.data || [];
    
    // Build usage map for each configuration
    const usage: Record<string, { suites: Array<{ id: string; name: string }>; harnesses: Array<{ id: string; name: string }> }> = {};
    
    configurations.value.forEach((config) => {
      // Find suites that use this configuration
      const suitesUsingConfig = testSuites.value.filter((suite: any) => 
        suite.testConfigurationIds && suite.testConfigurationIds.includes(config.id)
      );
      
      // Find harnesses that contain these suites
      const harnessIds = new Set<string>();
      suitesUsingConfig.forEach((suite: any) => {
        testHarnesses.value.forEach((harness: any) => {
          if (harness.testSuiteIds && harness.testSuiteIds.includes(suite.id)) {
            harnessIds.add(harness.id);
          }
        });
      });
      
      const harnesses = Array.from(harnessIds).map((id) => {
        const harness = testHarnesses.value.find((h: any) => h.id === id);
        return harness ? { id: harness.id, name: harness.name } : null;
      }).filter((h): h is { id: string; name: string } => h !== null);
      
      usage[config.id] = {
        suites: suitesUsingConfig.map((suite: any) => ({ id: suite.id, name: suite.name })),
        harnesses,
      };
    });
    
    configUsage.value = usage;
  } catch (err) {
    console.error('Error loading usage data:', err);
    configUsage.value = {};
  }
};

const loadRecentResults = async () => {
  // Load recent results for all configurations of this type
  try {
    const configIds = configurations.value.map(c => c.id);
    if (configIds.length === 0) {
      recentResults.value = [];
      return;
    }
    
    // Get recent results for all configs and combine
    const resultsPromises = configIds.map(async (configId) => {
      try {
        const response = await axios.get(`/api/test-results/test-configuration/${configId}?limit=2`);
        return response.data || [];
      } catch (err) {
        return [];
      }
    });
    
    const allResults = await Promise.all(resultsPromises);
    const combined = allResults.flat();
    
    // Sort by timestamp and take most recent 5
    combined.sort((a, b) => {
      const timeA = new Date(a.timestamp).getTime();
      const timeB = new Date(b.timestamp).getTime();
      return timeB - timeA;
    });
    
    recentResults.value = combined.slice(0, 5);
  } catch (err) {
    console.error('Error loading recent results:', err);
    recentResults.value = [];
  }
};

const handleCreateConfig = async (configData: any) => {
  try {
    await axios.post('/api/test-configurations', {
      ...configData,
      type: props.type
    });
    showCreateConfig.value = false;
    await loadConfigurations();
    await loadLastRunStatus();
    await loadUsageData();
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
  flex-direction: column;
  gap: 8px;
  flex: 1;
}

.config-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.config-name {
  font-weight: 500;
  color: #ffffff;
}

.config-usage {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.usage-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 0.8rem;
}

.usage-label {
  color: #a0aec0;
  font-weight: 500;
  min-width: 80px;
  flex-shrink: 0;
}

.usage-label.muted {
  color: #718096;
  font-style: italic;
}

.usage-badges {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  flex: 1;
}

.usage-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 150px;
}

.suite-badge {
  background: rgba(79, 172, 254, 0.15);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.harness-badge {
  background: rgba(34, 197, 94, 0.15);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
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

.info-banner {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 1rem;
  background: rgba(255, 193, 7, 0.1);
  border: 1px solid rgba(255, 193, 7, 0.3);
  border-radius: 8px;
  margin-bottom: 1rem;
  color: #ffc107;
}

.info-banner .info-icon {
  flex-shrink: 0;
  width: 18px;
  height: 18px;
}

.info-banner p {
  margin: 0;
  font-size: 0.875rem;
  line-height: 1.5;
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


