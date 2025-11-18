<template>
  <div class="test-suites-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Test Suites</h1>
          <p class="page-description">Collections of configurations grouped together. Test suites allow you to organize multiple tests and track results automatically in CI/CD.</p>
        </div>
        <button @click="router.push({ name: 'TestSuiteCreate' })" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Suite
        </button>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-cards">
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <List class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ testSuites.length || 0 }}</div>
          <div class="stat-label">Test Suites</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <TestTube class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ testTypes.length }}</div>
          <div class="stat-label">Test Types</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon-wrapper">
          <Settings class="stat-icon" />
        </div>
        <div class="stat-content">
          <div class="stat-value">{{ configurationsCount }}</div>
          <div class="stat-label">Configurations</div>
        </div>
      </div>
    </div>

    <!-- Test Suites List -->
    <div v-if="loadingSuites" class="loading">Loading test suites...</div>
    <div v-else-if="suitesError" class="error">{{ suitesError }}</div>
    <div v-else>
      <div class="filters">
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search test suites..."
          class="search-input"
        />
        <Dropdown
          v-model="filterApplication"
          :options="applicationOptions"
          placeholder="All Applications"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterTeam"
          :options="teamOptions"
          placeholder="All Teams"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterStatus"
          :options="statusOptions"
          placeholder="All Statuses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterValidator"
          :options="validatorOptions"
          placeholder="All Validators"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterHarness"
          :options="harnessOptions"
          placeholder="All Harnesses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="filterDomain"
          :options="domainOptions"
          placeholder="All Domains"
          class="filter-dropdown"
        />
      </div>

      <div class="test-suites-grid">
        <div
          v-for="suite in filteredTestSuites"
          :key="suite.id"
          class="test-suite-card"
          @click="viewTestSuite(suite.id)"
        >
          <div class="suite-header">
            <div class="suite-title-row">
              <h3 class="suite-name">{{ suite.name }}</h3>
              <div class="suite-status-badges">
                <span 
                  v-if="suite.sourceType"
                  class="source-type-badge"
                  :class="suite.sourceType === 'typescript' ? 'typescript' : 'json'"
                  :title="suite.sourceType === 'typescript' ? 'TypeScript source file' : 'JSON configuration'"
                >
                  {{ suite.sourceType === 'typescript' ? 'TS' : 'JSON' }}
                </span>
                <span 
                  class="enabled-badge"
                  :class="suite.enabled ? 'enabled' : 'disabled'"
                  :title="suite.enabled ? 'Enabled' : 'Disabled'"
                >
                  {{ suite.enabled ? 'Enabled' : 'Disabled' }}
                </span>
                <span class="suite-status" :class="`status-${suite.status}`">
                  {{ suite.status }}
                </span>
              </div>
            </div>
            <p class="suite-meta">
              {{ suite.application }} • {{ suite.team }}
              <span v-if="suite.sourcePath" class="source-path" :title="suite.sourcePath">
                • {{ suite.sourcePath }}
              </span>
            </p>
            <div v-if="suite.harnessNames && suite.harnessNames.length > 0" class="suite-harnesses">
              <span class="harness-label">In harnesses:</span>
              <span
                v-for="harnessName in suite.harnessNames"
                :key="harnessName.id"
                class="harness-badge"
                @click.stop="viewHarness(harnessName.id)"
                :title="`View ${harnessName.name} harness`"
              >
                {{ harnessName.name }}
              </span>
            </div>
          </div>
          
          <div class="suite-stats">
            <div class="stat">
              <span class="stat-label">Last Run</span>
              <span class="stat-value">{{ formatDate(suite.lastRun) }}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Tests</span>
              <span class="stat-value">{{ suite.testCount }}</span>
            </div>
            <div class="stat">
              <span class="stat-label">Score</span>
              <span class="stat-value score" :class="getScoreClass(suite.score)">
                {{ suite.score }}%
              </span>
            </div>
          </div>

          <div class="suite-types">
            <span
              v-for="type in suite.testTypes"
              :key="type"
              class="test-type-badge"
            >
              {{ type }}
            </span>
          </div>

          <div class="suite-actions">
            <button 
              @click.stop="toggleTestSuite(suite)" 
              class="action-btn"
              :class="{ 'warning-btn': !suite.enabled }"
              :title="suite.enabled ? 'Disable' : 'Enable'"
            >
              <Power class="action-icon" />
              {{ suite.enabled ? 'Disable' : 'Enable' }}
            </button>
            <button @click.stop="viewTestSuite(suite.id)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button 
              v-if="suite.sourceType === 'typescript'"
              @click.stop="editSource(suite.id)" 
              class="action-btn source-btn"
              title="Edit source file"
            >
              <Code class="action-icon" />
              Source
            </button>
            <button @click.stop="viewResults(suite.id)" class="action-btn view-btn">
              <FileText class="action-icon" />
              Results
            </button>
            <button @click.stop="deleteTestSuite(suite.id)" class="action-btn delete-btn">
              <Trash2 class="action-icon" />
              Delete
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredTestSuites.length === 0" class="empty-state">
        <TestTube class="empty-icon" />
        <h3>No test suites found</h3>
        <p>Create your first test suite to get started</p>
        <button @click="router.push({ name: 'TestSuiteCreate' })" class="btn-primary">
          Create Test Suite
        </button>
      </div>
    </div>
    
    <!-- Test Suite Source Editor -->
    <TestSuiteSourceEditor
      v-if="showSourceEditor"
      :suite-id="editingSourceSuiteId"
      @close="closeSourceEditor"
      @saved="handleSourceSaved"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  TestTube,
  FileText,
  Edit,
  Plus,
  List,
  Settings,
  Power,
  Code,
  Trash2
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestSuiteSourceEditor from '../components/TestSuiteSourceEditor.vue';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Test Suites' }
];

const testTypes = [
  { name: 'API Gateway', type: 'api-gateway' },
  { name: 'DLP', type: 'dlp' },
  { name: 'Network Policies', type: 'network-policy' },
  { name: 'API Security', type: 'api-security' },
  { name: 'RLS/CLS', type: 'rls-cls' },
  { name: 'Distributed Systems', type: 'distributed-systems' },
  { name: 'Data Pipeline', type: 'data-pipeline' }
];

const testSuites = ref<any[]>([]);
const loadingSuites = ref(false);
const suitesError = ref<string | null>(null);
const configurations = ref<any[]>([]);
const testHarnesses = ref<any[]>([]);
const validators = ref<any[]>([]);

const searchQuery = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterStatus = ref('');
const filterValidator = ref('');
const filterHarness = ref('');
const filterDomain = ref('');

const showSourceEditor = ref(false);
const editingSourceSuiteId = ref<string | null>(null);

const applications = computed(() => {
  return [...new Set(testSuites.value.map(s => s.application))];
});

const teams = computed(() => {
  return [...new Set(testSuites.value.map(s => s.team))];
});

const applicationOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applications.value.map(app => ({ label: app, value: app }))
  ];
});

const teamOptions = computed(() => {
  return [
    { label: 'All Teams', value: '' },
    ...teams.value.map(team => ({ label: team, value: team }))
  ];
});

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Passing', value: 'passing' },
  { label: 'Failing', value: 'failing' },
  { label: 'Pending', value: 'pending' }
]);

const validatorOptions = computed(() => {
  return [
    { label: 'All Validators', value: '' },
    ...validators.value.map(v => ({ label: v.name, value: v.id }))
  ];
});

const harnessOptions = computed(() => {
  return [
    { label: 'All Harnesses', value: '' },
    ...testHarnesses.value.map(h => ({ label: h.name, value: h.id }))
  ];
});

const domainOptions = computed(() => {
  const domains = new Set<string>();
  testSuites.value.forEach(suite => {
    if (suite.domain) {
      domains.add(suite.domain);
    }
  });
  
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

const filteredTestSuites = computed(() => {
  return testSuites.value.filter(suite => {
    const matchesSearch = !searchQuery.value || suite.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         (suite.application && suite.application.toLowerCase().includes(searchQuery.value.toLowerCase()));
    const matchesApp = !filterApplication.value || suite.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || suite.team === filterTeam.value;
    const matchesStatus = !filterStatus.value || suite.status === filterStatus.value;
    const matchesValidator = !filterValidator.value || (suite.validatorId === filterValidator.value);
    const matchesHarness = !filterHarness.value || (suite.harnessIds && suite.harnessIds.includes(filterHarness.value));
    const matchesDomain = !filterDomain.value || suite.domain === filterDomain.value;
    return matchesSearch && matchesApp && matchesTeam && matchesStatus && matchesValidator && matchesHarness && matchesDomain;
  });
});

const configurationsCount = computed(() => configurations.value.length);

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-excellent';
  if (score >= 70) return 'score-good';
  if (score >= 50) return 'score-warning';
  return 'score-poor';
};

const formatDate = (date: Date | undefined): string => {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};


const loadTestSuites = async () => {
  loadingSuites.value = true;
  suitesError.value = null;
  try {
    const [suitesResponse, harnessesResponse] = await Promise.all([
      axios.get('/api/test-suites'),
      axios.get('/api/test-harnesses'),
    ]);
    
    const allHarnesses = harnessesResponse.data || [];
    
    testSuites.value = suitesResponse.data.map((s: any) => {
      const containingHarnesses = allHarnesses.filter((h: any) => 
        h.testSuiteIds && h.testSuiteIds.includes(s.id)
      );
      
      return {
        ...s,
        application: s.application || s.applicationId,
        lastRun: s.lastRun ? new Date(s.lastRun) : undefined,
        createdAt: s.createdAt ? new Date(s.createdAt) : new Date(),
        updatedAt: s.updatedAt ? new Date(s.updatedAt) : new Date(),
        sourceType: s.sourceType || 'json',
        sourcePath: s.sourcePath,
        harnessIds: containingHarnesses.map((h: any) => h.id),
        harnessNames: containingHarnesses.map((h: any) => ({ id: h.id, name: h.name })),
      };
    });
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to load test suites';
    console.error('Error loading test suites:', err);
  } finally {
    loadingSuites.value = false;
  }
};


const loadConfigurations = async () => {
  try {
    const response = await axios.get('/api/test-configurations');
    configurations.value = response.data || [];
  } catch (err) {
    console.error('Error loading configurations:', err);
  }
};

const loadTestHarnesses = async () => {
  try {
    const response = await axios.get('/api/test-harnesses');
    testHarnesses.value = response.data || [];
  } catch (err) {
    console.error('Error loading test harnesses:', err);
  }
};

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data || [];
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

const deleteTestSuite = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test suite? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-suites/${id}`);
    await loadTestSuites();
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to delete test suite';
    console.error('Error deleting test suite:', err);
    alert(err.response?.data?.message || 'Failed to delete test suite');
  }
};

const toggleTestSuite = async (suite: any) => {
  try {
    if (suite.enabled) {
      await axios.patch(`/api/test-suites/${suite.id}/disable`);
    } else {
      await axios.patch(`/api/test-suites/${suite.id}/enable`);
    }
    await loadTestSuites();
  } catch (err: any) {
    suitesError.value = err.response?.data?.message || 'Failed to toggle test suite';
    console.error('Error toggling test suite:', err);
    alert(err.response?.data?.message || 'Failed to toggle test suite');
  }
};

const viewTestSuite = (id: string) => {
  router.push({ name: 'TestSuiteDetail', params: { id } });
};

const viewResults = (id: string) => {
  router.push({ path: '/tests/findings', query: { suite: id } });
};


const viewHarness = (id: string) => {
  router.push({ path: `/tests/harnesses/${id}` });
};

const editSource = (id: string) => {
  editingSourceSuiteId.value = id;
  showSourceEditor.value = true;
};

const closeSourceEditor = () => {
  showSourceEditor.value = false;
  editingSourceSuiteId.value = null;
};

const handleSourceSaved = async () => {
  await loadTestSuites();
  closeSourceEditor();
};

onMounted(async () => {
  await Promise.all([
    loadValidators(),
    loadTestSuites(),
    loadConfigurations(),
    loadTestHarnesses()
  ]);
});
</script>

<style scoped>
.test-suites-page {
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
  gap: 1.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: all 0.2s;
}

.stat-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 2px 8px rgba(79, 172, 254, 0.1);
}

.stat-icon-wrapper {
  width: 48px;
  height: 48px;
  border-radius: 8px;
  background: rgba(79, 172, 254, 0.1);
  display: flex;
  align-items: center;
  justify-content: center;
}

.stat-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}



.filters {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 0.75rem;
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
}

.search-input::placeholder {
  color: #6b7280;
}

.filter-dropdown {
  min-width: 150px;
}

.test-suites-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.test-suite-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.test-suite-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.2);
}

.suite-header {
  margin-bottom: 1rem;
}

.suite-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
  gap: 1rem;
}

.suite-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.suite-status-badges {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.source-type-badge,
.enabled-badge,
.suite-status {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.source-type-badge.typescript {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.source-type-badge.json {
  background: rgba(139, 92, 246, 0.2);
  color: #a78bfa;
}

.enabled-badge.enabled {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.enabled-badge.disabled {
  background: rgba(107, 114, 128, 0.2);
  color: #6b7280;
}

.suite-status.status-passing {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.suite-status.status-failing {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.suite-status.status-pending {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.suite-meta {
  color: #a0aec0;
  font-size: 0.875rem;
  margin: 0 0 0.75rem 0;
}

.source-path {
  opacity: 0.7;
}

.suite-harnesses {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 0.5rem;
}

.harness-label {
  color: #a0aec0;
  font-size: 0.75rem;
}

.harness-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
  cursor: pointer;
  transition: all 0.2s;
}

.harness-badge:hover {
  background: rgba(79, 172, 254, 0.3);
}

.suite-stats {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.suite-stats .stat {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.suite-stats .stat-label {
  color: #a0aec0;
  font-size: 0.75rem;
}

.suite-stats .stat-value {
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 600;
}

.suite-stats .stat-value.score {
  font-size: 1rem;
}

.score.score-excellent {
  color: #22c55e;
}

.score.score-good {
  color: #4facfe;
}

.score.score-warning {
  color: #f59e0b;
}

.score.score-poor {
  color: #ef4444;
}

.suite-types {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.test-type-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(139, 92, 246, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #a78bfa;
}

.suite-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.4);
}

.action-btn.warning-btn {
  color: #f59e0b;
  border-color: rgba(245, 158, 11, 0.2);
}

.action-btn.warning-btn:hover {
  background: rgba(245, 158, 11, 0.1);
  border-color: rgba(245, 158, 11, 0.4);
}

.action-btn.delete-btn {
  color: #ef4444;
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
  color: #4facfe;
  margin: 0 auto 1rem;
  opacity: 0.5;
}

.empty-state h3 {
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.empty-state p {
  color: #a0aec0;
  margin-bottom: 1.5rem;
}

.loading, .error {
  padding: 2rem;
  text-align: center;
}

.error {
  color: #fc8181;
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

