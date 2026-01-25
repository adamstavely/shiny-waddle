<template>
  <div class="individual-tests-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Individual Tests</h1>
          <p class="page-description">Manage and organize individual test configurations. Each test validates specific security requirements using policies and infrastructure.</p>
        </div>
        <button @click="router.push({ name: 'TestCreate' })" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test
        </button>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-cards">
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <TestTube class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ tests.length || 0 }}</div>
          <div class="stat-label">Total Tests</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <Shield class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ accessControlTestsCount }}</div>
          <div class="stat-label">Access Control</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <Database class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ otherTestsCount }}</div>
          <div class="stat-label">Other Types</div>
        </div>
      </div>
    </div>

    <!-- Tests List -->
    <div v-if="loading" class="loading">Loading tests...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else>
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search tests..."
          class="search-input"
        />
        <Dropdown
          v-model="filterCategory"
          :options="categoryOptions"
          placeholder="All Categories"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterTestType"
          :options="filteredTestTypeOptions"
          placeholder="All Test Types"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterDomain"
          :options="domainOptions"
          placeholder="All Domains"
          class="filter-dropdown"
        />
      </div>

      <div class="tests-grid">
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
            <p v-if="test.description" class="test-description">{{ test.description }}</p>
            <div class="test-meta">
              <span class="test-type-badge" :class="`type-${test.testType}`">
                {{ getTestTypeLabel(test.testType) }}
              </span>
              <span v-if="test.domain" class="domain-badge">
                {{ getDomainLabel(test.domain) }}
              </span>
            </div>
          </div>
          
          <div class="test-info">
            <div v-if="test.testType === 'access-control' && test.policyId" class="info-row">
              <span class="info-label">Policy:</span>
              <span class="info-value">{{ getPolicyName(test.policyId) }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Created:</span>
              <span class="info-value">{{ formatDate(test.createdAt) }}</span>
            </div>
            <div class="info-row">
              <span class="info-label">Last Updated:</span>
              <span class="info-value">{{ formatDate(test.updatedAt) }}</span>
            </div>
          </div>

          <div class="test-actions">
            <button @click.stop="viewTest(test.id)" class="action-btn view-btn">
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

      <div v-if="filteredTests.length === 0" class="empty-state">
        <TestTube class="empty-icon" />
        <h3>No tests found</h3>
        <p>Create your first test to get started</p>
        <button @click="router.push({ name: 'TestCreate' })" class="btn-primary">
          Create Test
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import {
  TestTube,
  Shield,
  Database,
  Plus,
  Eye,
  Edit,
  Trash2
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const router = useRouter();
const route = useRoute();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Individual Tests' }
];

const tests = ref<any[]>([]);
const policies = ref<any[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);

const searchQuery = ref('');
const filterCategory = ref('');
const filterTestType = ref('');
const filterDomain = ref('');

const testTypeOptionsByCategory = {
  'Access & Security': [
    { label: 'Access Control', value: 'access-control' },
    { label: 'Network Policy', value: 'network-policy' },
    { label: 'Data Loss Prevention (DLP)', value: 'dlp' },
    { label: 'API Security', value: 'api-security' },
    { label: 'API Gateway', value: 'api-gateway' },
    { label: 'RLS/CLS', value: 'rls-cls' },
  ],
  'Platform Configuration': [
    { label: 'Salesforce Config', value: 'salesforce-config' },
    { label: 'Salesforce Security', value: 'salesforce-security' },
    { label: 'Salesforce Experience Cloud', value: 'salesforce-experience-cloud' },
    { label: 'Elastic Config', value: 'elastic-config' },
    { label: 'Elastic Security', value: 'elastic-security' },
    { label: 'Kubernetes Security', value: 'k8s-security' },
    { label: 'Kubernetes Workload', value: 'k8s-workload' },
    { label: 'IDP Compliance', value: 'idp-compliance' },
    { label: 'ServiceNow Config', value: 'servicenow-config' },
  ],
  'Distributed Systems': [
    { label: 'Multi-Region', value: 'distributed-systems:multi-region' },
    { label: 'Policy Consistency', value: 'distributed-systems:policy-consistency' },
    { label: 'Policy Synchronization', value: 'distributed-systems:policy-synchronization' },
  ],
  'Data & Systems': [
    { label: 'Data Pipeline', value: 'data-pipeline' },
    { label: 'Data Contract', value: 'data-contract' },
    { label: 'Dataset Health', value: 'dataset-health' },
  ],
  'Environment Configuration': [
    { label: 'Environment Config', value: 'environment-config' },
    { label: 'Secrets Management', value: 'secrets-management' },
    { label: 'Configuration Drift', value: 'config-drift' },
    { label: 'Environment Policies', value: 'environment-policies' },
  ],
};

const categoryOptions = [
  { label: 'All Categories', value: '' },
  { label: 'Access & Security', value: 'Access & Security' },
  { label: 'Platform Configuration', value: 'Platform Configuration' },
  { label: 'Distributed Systems', value: 'Distributed Systems' },
  { label: 'Data & Systems', value: 'Data & Systems' },
  { label: 'Environment Configuration', value: 'Environment Configuration' },
];

const filteredTestTypeOptions = computed(() => {
  if (filterCategory.value) {
    const types = testTypeOptionsByCategory[filterCategory.value as keyof typeof testTypeOptionsByCategory] || [];
    return [
      { label: 'All Test Types', value: '' },
      ...types
    ];
  }
  // If no category selected, show all test types
  return testTypeOptions.value;
});

const testTypeOptions = computed(() => {
  // Include all possible test types, not just ones that exist
  const allTestTypes = [
    'access-control',
    'dataset-health',
    'rls-cls',
    'network-policy',
    'dlp',
    'api-gateway',
    'distributed-systems',
    'api-security',
    'data-pipeline',
    'data-contract',
    'salesforce-config',
    'salesforce-security',
    'salesforce-experience-cloud',
    'elastic-config',
    'elastic-security',
    'k8s-security',
    'k8s-workload',
    'idp-compliance',
    'servicenow-config',
    'environment-config',
    'secrets-management',
    'config-drift',
    'environment-policies'
  ];
  
  const typeLabels: Record<string, string> = {
    'access-control': 'Access Control',
    'dataset-health': 'Dataset Health',
    'rls-cls': 'RLS/CLS',
    'network-policy': 'Network Policy',
    'dlp': 'DLP',
    'api-gateway': 'API Gateway',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
    'data-contract': 'Data Contract',
    'salesforce-config': 'Salesforce Config',
    'salesforce-security': 'Salesforce Security',
    'salesforce-experience-cloud': 'Salesforce Experience Cloud',
    'elastic-config': 'Elastic Config',
    'elastic-security': 'Elastic Security',
    'k8s-security': 'K8s Security',
    'k8s-workload': 'K8s Workload',
    'idp-compliance': 'IDP Compliance',
    'servicenow-config': 'ServiceNow Config',
    'environment-config': 'Environment Config',
    'secrets-management': 'Secrets Management',
    'config-drift': 'Configuration Drift',
    'environment-policies': 'Environment Policies'
  };
  
  return [
    { label: 'All Test Types', value: '' },
    ...allTestTypes.map(t => ({
      label: typeLabels[t] || t,
      value: t
    }))
  ];
});

const domainOptions = computed(() => {
  const domains = new Set(tests.value.map(t => t.domain).filter(Boolean));
  const domainLabels: Record<string, string> = {
    'api_security': 'API Security',
    'platform_config': 'Platform Configuration',
    'identity': 'Identity',
    'data_contracts': 'Data Contracts',
    'salesforce': 'Salesforce',
    'elastic': 'Elastic',
    'idp_platform': 'IDP / Kubernetes',
  };
  
  return [
    { label: 'All Domains', value: '' },
    ...Array.from(domains).map(d => ({
      label: domainLabels[d] || d,
      value: d
    }))
  ];
});

const filteredTests = computed(() => {
  return tests.value.filter(test => {
    const matchesSearch = !searchQuery.value || 
      test.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      (test.description && test.description.toLowerCase().includes(searchQuery.value.toLowerCase()));
    
    // Check if test type matches category filter
    const matchesCategory = !filterCategory.value || 
      (testTypeOptionsByCategory[filterCategory.value as keyof typeof testTypeOptionsByCategory] || [])
        .some(opt => {
          if (filterCategory.value === 'Distributed Systems') {
            // For distributed systems, check if test has distributedTestType matching the option
            const optValue = opt.value as string;
            if (optValue.startsWith('distributed-systems:')) {
              const expectedType = optValue.split(':')[1];
              return test.testType === 'distributed-systems' && test.distributedTestType === expectedType;
            }
            return false;
          }
          // For other categories, check if testType matches
          return opt.value === test.testType;
        });
    
    const matchesType = !filterTestType.value || test.testType === filterTestType.value;
    const matchesDomain = !filterDomain.value || test.domain === filterDomain.value;
    return matchesSearch && matchesCategory && matchesType && matchesDomain;
  });
});

const accessControlTestsCount = computed(() => {
  return tests.value.filter(t => t.testType === 'access-control').length;
});

const otherTestsCount = computed(() => {
  return tests.value.filter(t => t.testType !== 'access-control').length;
});

const getTestTypeLabel = (testType: string): string => {
  const labels: Record<string, string> = {
    'access-control': 'Access Control',
    'dataset-health': 'Dataset Health',
    'rls-cls': 'RLS/CLS',
    'network-policy': 'Network Policy',
    'dlp': 'DLP',
    'api-gateway': 'API Gateway',
    'distributed-systems': 'Distributed Systems',
    'api-security': 'API Security',
    'data-pipeline': 'Data Pipeline',
    'data-contract': 'Data Contract',
    'salesforce-config': 'Salesforce Config',
    'salesforce-security': 'Salesforce Security',
    'salesforce-experience-cloud': 'Salesforce Experience Cloud',
    'elastic-config': 'Elastic Config',
    'elastic-security': 'Elastic Security',
    'k8s-security': 'K8s Security',
    'k8s-workload': 'K8s Workload',
    'idp-compliance': 'IDP Compliance',
    'servicenow-config': 'ServiceNow Config',
    'environment-config': 'Environment Config',
    'secrets-management': 'Secrets Management',
    'config-drift': 'Configuration Drift',
    'environment-policies': 'Environment Policies',
  };
  return labels[testType] || testType;
};

const getDomainLabel = (domain: string): string => {
  const labels: Record<string, string> = {
    'api_security': 'API Security',
    'platform_config': 'Platform Configuration',
    'identity': 'Identity',
    'data_contracts': 'Data Contracts',
    'salesforce': 'Salesforce',
    'elastic': 'Elastic',
    'idp_platform': 'IDP / Kubernetes',
  };
  return labels[domain] || domain;
};

const getPolicyName = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.name || policyId;
};

const formatDate = (date: Date | string | undefined): string => {
  if (!date) return 'Never';
  const d = new Date(date);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
};

const loadTests = async () => {
  loading.value = true;
  error.value = null;
  try {
    const policyId = route.query.policyId as string;
    const params: any = {};
    if (policyId) {
      params.policyId = policyId;
    }
    
    const response = await axios.get('/api/v1/tests', { params });
    tests.value = (response.data || []).map((t: any) => ({
      ...t,
      createdAt: t.createdAt ? new Date(t.createdAt) : new Date(),
      updatedAt: t.updatedAt ? new Date(t.updatedAt) : new Date(),
    }));
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
    policies.value = response.data || [];
  } catch (err) {
    console.error('Error loading policies:', err);
  }
};

const viewTest = (id: string) => {
  router.push({ path: `/tests/test/${id}` });
};

const editTest = (id: string) => {
  router.push({ name: 'TestEdit', params: { id } });
};

const deleteTest = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/v1/tests/${id}`);
    await loadTests();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to delete test';
    console.error('Error deleting test:', err);
    alert(err.response?.data?.message || 'Failed to delete test');
  }
};

onMounted(async () => {
  await Promise.all([
    loadTests(),
    loadPolicies()
  ]);
});
</script>

<style scoped>
.individual-tests-page {
  padding: var(--spacing-xl);
  max-width: 1800px;
  margin: 0 auto;
  width: 100%;
}

.page-header {
  margin-bottom: var(--spacing-xl);
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: var(--spacing-lg);
}

.page-title {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  color: var(--color-text-secondary);
  margin: 0;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.stat-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  transition: var(--transition-all);
}

.stat-card:hover {
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-sm);
}

.stat-icon-wrapper {
  width: 48px;
  height: 48px;
  border-radius: var(--border-radius-md);
  background: rgba(79, 172, 254, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
}

.stat-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.filters {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 0.75rem;
  background: rgba(26, 31, 46, 0.6);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
}

.search-input::placeholder {
  color: var(--color-text-muted);
}

.filter-dropdown {
  min-width: 150px;
}

.tests-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
  margin-bottom: var(--spacing-xl);
}

.test-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.test-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary);
}

.test-header {
  margin-bottom: 1rem;
}

.test-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
  gap: 1rem;
}

.test-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.version-badge {
  padding: 0.25rem 0.75rem;
  background: var(--color-info-bg);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
  color: var(--color-primary);
}

.test-description {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin: 0 0 0.75rem 0;
  line-height: 1.5;
}

.test-meta {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.test-type-badge,
.domain-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: 500;
}

.test-type-badge.type-access-control {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.test-type-badge.type-dataset-health {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.test-type-badge.type-rls-cls {
  background: rgba(139, 92, 246, 0.2);
  color: #a78bfa;
}

.test-type-badge {
  background: rgba(139, 92, 246, 0.2);
  color: #a78bfa;
}

.domain-badge {
  background: rgba(107, 114, 128, 0.2);
  color: #9ca3af;
}

.test-info {
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.info-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.info-label {
  color: var(--color-text-secondary);
}

.info-value {
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.test-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover {
  background: var(--border-color-primary);
  border-color: var(--border-color-primary-hover);
}

.action-btn.edit-btn {
  color: var(--color-primary);
}

.action-btn.delete-btn {
  color: var(--color-error-dark);
  border-color: rgba(239, 68, 68, 0.2);
}

.action-btn.delete-btn:hover {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.4);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.empty-state h3 {
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.loading, .error {
  padding: var(--spacing-xl);
  text-align: center;
}

.error {
  color: var(--color-error);
}

.btn-primary {
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-xl);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
  border: none;
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: var(--shadow-primary);
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
