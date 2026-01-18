<template>
  <div class="tests-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Tests</h1>
          <p class="page-description">Manage individual reusable tests that can be assigned to test suites</p>
        </div>
        <router-link to="/tests/individual/new" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test
        </router-link>
      </div>
    </div>

    <!-- Test Health Dashboard -->
    <div class="health-dashboard">
      <h3 class="section-title">Test Health</h3>
      <div class="health-stats">
        <div class="health-item">
          <div class="health-label">Pass Rate</div>
          <div class="health-value" :class="getHealthClass(passRate)">
            {{ passRate.toFixed(1) }}%
          </div>
        </div>
        <div class="health-item">
          <div class="health-label">Active Suites</div>
          <div class="health-value">
            {{ activeSuitesCount }}
          </div>
        </div>
        <div class="health-item">
          <div class="health-label">Last 24h Runs</div>
          <div class="health-value">
            {{ last24hRuns }}
          </div>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search tests..."
        class="search-input"
      />
      <Dropdown
        v-model="filterType"
        :options="typeOptions"
        placeholder="All Types"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterDomain"
        :options="domainOptions"
        placeholder="All Domains"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterPolicy"
        :options="policyOptions"
        placeholder="All Policies"
        class="filter-dropdown"
      />
    </div>

    <!-- Loading State -->
    <div v-if="loading && tests.length === 0" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading tests...</p>
    </div>

    <!-- Error State -->
    <div v-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadTests" class="btn-retry">Retry</button>
    </div>

    <!-- Tests List -->
    <div v-if="!loading || tests.length > 0" class="tests-grid">
      <div
        v-for="test in filteredTests"
        :key="test.id"
        class="test-card"
        @click="viewTest(test.id)"
      >
        <div class="test-header">
          <div class="test-title-row">
            <h3 class="test-name">{{ test.name }}</h3>
            <span class="version-badge">v{{ test.version }}</span>
          </div>
          <p class="test-meta">
            {{ getTestTypeLabel(test.testType) }}
          </p>
        </div>

        <p v-if="test.description" class="test-description">{{ test.description }}</p>

        <!-- Policy Info for Access Control Tests -->
        <div v-if="test.testType === 'access-control' && test.policyIds && test.policyIds.length > 0" class="test-policies">
          <span class="policies-label">Policies:</span>
          <span
            v-for="policyId in test.policyIds"
            :key="policyId"
            class="policy-badge"
            @click.stop="viewPolicy(policyId)"
          >
            {{ getPolicyName(policyId) }}
          </span>
        </div>

        <div class="test-stats">
          <div class="stat">
            <span class="stat-label">Version</span>
            <span class="stat-value">v{{ test.version }}</span>
          </div>
          <div class="stat">
            <span class="stat-label">Last Updated</span>
            <span class="stat-value">{{ formatDate(test.updatedAt) }}</span>
          </div>
        </div>

        <div class="test-actions">
          <button @click.stop="viewTest(test.id)" class="action-btn">
            <Eye class="action-icon" />
            View
          </button>
          <button @click.stop="editTest(test.id)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click.stop="deleteTest(test.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <!-- Empty State -->
    <div v-if="!loading && tests.length === 0" class="empty-state">
      <TestTube class="empty-icon" />
      <h3>No Tests Found</h3>
      <p>Create your first test to get started</p>
      <router-link to="/tests/individual/new" class="btn-primary">
        <Plus class="btn-icon" />
        Create Test
      </router-link>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import {
  Plus,
  Eye,
  Edit,
  Trash2,
  AlertTriangle,
  TestTube,
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import Dropdown from '../components/Dropdown.vue';

const router = useRouter();
const route = useRoute();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
];

const tests = ref<any[]>([]);
const policies = ref<any[]>([]);
const testResults = ref<any[]>([]);
const testSuites = ref<any[]>([]);
const loading = ref(true);
const error = ref<string | null>(null);
const searchQuery = ref('');
const filterType = ref('');
const filterDomain = ref('');
const filterPolicy = ref('');

const typeOptions = [
  { value: '', label: 'All Types' },
  { value: 'access-control', label: 'Access Control' },
  { value: 'network-policy', label: 'Network Policy' },
  { value: 'dlp', label: 'Data Loss Prevention (DLP)' },
  { value: 'distributed-systems', label: 'Distributed Systems' },
  { value: 'api-security', label: 'API Security' },
  { value: 'data-pipeline', label: 'Data Pipeline' },
  { value: 'data-contract', label: 'Data Contract' },
  { value: 'salesforce-config', label: 'Salesforce Config' },
  { value: 'salesforce-security', label: 'Salesforce Security' },
  { value: 'elastic-config', label: 'Elastic Config' },
  { value: 'elastic-security', label: 'Elastic Security' },
  { value: 'k8s-security', label: 'K8s Security' },
  { value: 'k8s-workload', label: 'K8s Workload' },
  { value: 'idp-compliance', label: 'IDP Compliance' },
];

const domainOptions = [
  { value: '', label: 'All Domains' },
  { value: 'api_security', label: 'API Security' },
  { value: 'platform_config', label: 'Platform Configuration' },
  { value: 'identity', label: 'Identity' },
  { value: 'data_contracts', label: 'Data Contracts' },
  { value: 'salesforce', label: 'Salesforce' },
  { value: 'elastic', label: 'Elastic' },
  { value: 'idp_platform', label: 'IDP / Kubernetes' },
];

const policyOptions = computed(() => {
  const options = [{ value: '', label: 'All Policies' }];
  const uniquePolicies = new Set<string>();
  
  tests.value.forEach(test => {
    if (test.testType === 'access-control' && test.policyIds) {
      test.policyIds.forEach((pid: string) => uniquePolicies.add(pid));
    }
  });
  
  uniquePolicies.forEach(pid => {
    const policy = policies.value.find(p => p.id === pid);
    if (policy) {
      options.push({ value: pid, label: policy.name });
    }
  });
  
  return options;
});

const filteredTests = computed(() => {
  let filtered = [...tests.value];
  
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase();
    filtered = filtered.filter(t =>
      t.name.toLowerCase().includes(query) ||
      (t.description && t.description.toLowerCase().includes(query))
    );
  }
  
  if (filterType.value) {
    filtered = filtered.filter(t => t.testType === filterType.value);
  }
  
  if (filterDomain.value) {
    filtered = filtered.filter(t => t.domain === filterDomain.value);
  }
  
  if (filterPolicy.value) {
    filtered = filtered.filter(t => {
      if (t.testType === 'access-control' && t.policyIds) {
        return t.policyIds.includes(filterPolicy.value);
      }
      return false;
    });
  }
  
  return filtered;
});

const loadTests = async () => {
  loading.value = true;
  error.value = null;
  try {
    const params: any = {};
    if (filterType.value) params.testType = filterType.value;
    if (filterDomain.value) params.domain = filterDomain.value;
    if (filterPolicy.value) params.policyId = filterPolicy.value;
    
    const response = await axios.get('/api/v1/tests', { params });
    tests.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load tests';
    console.error('Error loading tests:', err);
  } finally {
    loading.value = false;
  }
};

const loadPolicies = async () => {
  try {
    const response = await axios.get('/api/policies');
    policies.value = response.data;
  } catch (err) {
    console.error('Error loading policies:', err);
  }
};

const loadTestResults = async () => {
  try {
    const response = await axios.get('/api/test-results?limit=100');
    if (response.data) {
      testResults.value = response.data.map((r: any) => ({
        ...r,
        timestamp: r.timestamp ? new Date(r.timestamp) : new Date(),
        passed: r.status === 'passed' || r.passed === true
      }));
    }
  } catch (err) {
    console.error('Error loading test results:', err);
  }
};

const loadTestSuites = async () => {
  try {
    const response = await axios.get('/api/v1/test-suites');
    testSuites.value = response.data || [];
  } catch (err) {
    console.error('Error loading test suites:', err);
  }
};

const getTestTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'network-policy': 'Network Policy',
    'dlp': 'Data Loss Prevention (DLP)',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
    'data-contract': 'Data Contract',
    'salesforce-config': 'Salesforce Config',
    'salesforce-security': 'Salesforce Security',
    'elastic-config': 'Elastic Config',
    'elastic-security': 'Elastic Security',
    'k8s-security': 'K8s Security',
    'k8s-workload': 'K8s Workload',
    'idp-compliance': 'IDP Compliance',
  };
  return labels[type] || type;
};

const getPolicyName = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.name || policyId;
};

const passRate = computed(() => {
  if (!testResults.value || testResults.value.length === 0) return 0;
  const passed = testResults.value.filter(r => r.passed).length;
  return (passed / testResults.value.length) * 100;
});

const activeSuitesCount = computed(() => {
  if (!testSuites.value) return 0;
  return testSuites.value.filter(s => s.enabled).length;
});

const last24hRuns = computed(() => {
  if (!testResults.value) return 0;
  const now = new Date();
  const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  return testResults.value.filter(r => {
    const timestamp = r.timestamp instanceof Date ? r.timestamp : new Date(r.timestamp);
    return timestamp >= yesterday;
  }).length;
});

const getHealthClass = (rate: number): string => {
  if (rate >= 90) return 'health-excellent';
  if (rate >= 70) return 'health-good';
  if (rate >= 50) return 'health-warning';
  return 'health-poor';
};

const viewTest = (id: string) => {
  router.push(`/tests/test/${id}`);
};

const editTest = (id: string) => {
  router.push(`/tests/individual/${id}/edit`);
};

const deleteTest = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test?')) {
    return;
  }
  
  try {
    await axios.delete(`/api/tests/${id}`);
    await loadTests();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete test';
    console.error('Error deleting test:', err);
  }
};

const viewPolicy = (policyId: string) => {
  router.push(`/policies/${policyId}`);
};

const handleTestSaved = () => {
  loadTests();
};

const formatDate = (date: Date | string): string => {
  if (!date) return 'Never';
  const d = new Date(date);
  return d.toLocaleDateString();
};

// Watch for filter changes and reload
watch([filterType, filterDomain, filterPolicy], () => {
  loadTests();
});

onMounted(async () => {
  await Promise.all([loadTests(), loadPolicies(), loadTestResults(), loadTestSuites()]);
  
  // Check for policyId query parameter
  const policyId = route.query.policyId as string;
  if (policyId) {
    filterPolicy.value = policyId;
  }
});
</script>

<style scoped>
.tests-page {
  padding: 2rem;
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
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
  margin: 0 0 0.5rem 0;
  color: #ffffff;
}

.page-description {
  color: rgba(255, 255, 255, 0.7);
  margin: 0;
}

.filters {
  display: flex;
  gap: 1rem;
  margin-bottom: 2rem;
}

.search-input {
  flex: 1;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
}

.filter-dropdown {
  min-width: 150px;
}

.tests-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 1.5rem;
}

.test-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.test-card:hover {
  border-color: rgba(79, 172, 254, 0.5);
  transform: translateY(-2px);
}

.test-header {
  margin-bottom: 1rem;
}

.test-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.test-name {
  font-size: 1.25rem;
  font-weight: 600;
  margin: 0;
  color: #ffffff;
}

.version-badge {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 600;
}

.test-meta {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
  margin: 0;
}

.test-description {
  color: rgba(255, 255, 255, 0.8);
  font-size: 0.9rem;
  margin: 0 0 1rem 0;
}

.test-policies {
  margin: 1rem 0;
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  align-items: center;
}

.policies-label {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.875rem;
}

.policy-badge {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  cursor: pointer;
  transition: background 0.2s;
}

.policy-badge:hover {
  background: rgba(79, 172, 254, 0.3);
}

.test-stats {
  display: flex;
  gap: 1.5rem;
  margin: 1rem 0;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.stat {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.stat-label {
  color: rgba(255, 255, 255, 0.6);
  font-size: 0.75rem;
}

.stat-value {
  color: #ffffff;
  font-size: 0.9rem;
  font-weight: 600;
}

.test-actions {
  display: flex;
  gap: 0.5rem;
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.action-btn {
  flex: 1;
  padding: 0.5rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: 4rem 2rem;
  color: rgba(255, 255, 255, 0.7);
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 1rem;
  color: rgba(79, 172, 254, 0.5);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid rgba(79, 172, 254, 0.2);
  border-top-color: #4facfe;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 1rem;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.health-dashboard {
  margin-bottom: 2rem;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 1rem;
}

.health-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
}

.health-item {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  text-align: center;
  transition: all 0.2s;
}

.health-item:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 2px 8px rgba(79, 172, 254, 0.1);
}

.health-label {
  color: rgba(255, 255, 255, 0.7);
  font-size: 0.875rem;
  margin-bottom: 0.5rem;
}

.health-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #ffffff;
}

.health-value.health-excellent {
  color: #22c55e;
}

.health-value.health-good {
  color: #4facfe;
}

.health-value.health-warning {
  color: #f59e0b;
}

.health-value.health-poor {
  color: #ef4444;
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
}

.btn-primary .btn-icon {
  width: 16px;
  height: 16px;
}
</style>

