<template>
  <div class="tests-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Tests</h1>
          <p class="page-description">Manage and run compliance test suites</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Test Suite
        </button>
      </div>
    </div>

    <!-- Tabs -->
    <div class="tabs">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        @click="activeTab = tab.id"
        class="tab-button"
        :class="{ active: activeTab === tab.id }"
      >
        <component :is="tab.icon" class="tab-icon" />
        {{ tab.label }}
        <span v-if="tab.badge" class="tab-badge">{{ tab.badge }}</span>
      </button>
    </div>

    <!-- Test Suites List -->
    <div v-if="activeTab === 'suites'" class="tab-content">
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
              <span class="suite-status" :class="`status-${suite.status}`">
                {{ suite.status }}
              </span>
            </div>
            <p class="suite-meta">{{ suite.application }} • {{ suite.team }}</p>
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
            <button @click.stop="runTestSuite(suite.id)" class="action-btn run-btn">
              <Play class="action-icon" />
              Run
            </button>
            <button @click.stop="editTestSuite(suite.id)" class="action-btn edit-btn">
              <Edit class="action-icon" />
              Edit
            </button>
            <button @click.stop="viewResults(suite.id)" class="action-btn view-btn">
              <FileText class="action-icon" />
              Results
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredTestSuites.length === 0" class="empty-state">
        <TestTube class="empty-icon" />
        <h3>No test suites found</h3>
        <p>Create your first test suite to get started</p>
        <button @click="showCreateModal = true" class="btn-primary">
          Create Test Suite
        </button>
      </div>
    </div>

    <!-- Test Execution -->
    <div v-if="activeTab === 'execution'" class="tab-content">
      <div v-if="!currentExecution" class="empty-state">
        <Play class="empty-icon" />
        <h3>No test execution in progress</h3>
        <p>Select a test suite and click "Run" to start execution</p>
      </div>
      <div v-else class="execution-view">
        <div class="execution-header">
          <div>
            <h2>{{ currentExecution.suiteName }}</h2>
            <p class="execution-status" :class="`status-${currentExecution.status}`">
              {{ currentExecution.status }}
            </p>
          </div>
          <div class="execution-progress">
            <div class="progress-bar">
              <div
                class="progress-fill"
                :style="{ width: `${currentExecution.progress}%` }"
              ></div>
            </div>
            <span class="progress-text">
              {{ currentExecution.completed }}/{{ currentExecution.total }} tests
            </span>
          </div>
        </div>

        <div class="execution-log">
          <div
            v-for="(log, index) in currentExecution.logs"
            :key="index"
            class="log-entry"
            :class="`log-${log.level}`"
          >
            <span class="log-time">{{ formatTime(log.timestamp) }}</span>
            <span class="log-message">{{ log.message }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Test Results -->
    <div v-if="activeTab === 'results'" class="tab-content">
      <div class="results-filters">
        <Dropdown
          v-model="resultsFilterSuite"
          :options="testSuiteOptions"
          placeholder="All Test Suites"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterStatus"
          :options="resultsStatusOptions"
          placeholder="All Results"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterType"
          :options="resultsTypeOptions"
          placeholder="All Types"
          class="filter-dropdown"
        />
      </div>

      <div class="results-list">
        <div
          v-for="result in filteredResults"
          :key="result.id"
          class="result-card"
          @click="viewResultDetails(result.id)"
        >
          <div class="result-header">
            <div class="result-title-row">
              <h4 class="result-name">{{ result.testName }}</h4>
              <span class="result-status" :class="result.passed ? 'status-passed' : 'status-failed'">
                {{ result.passed ? 'Passed' : 'Failed' }}
              </span>
            </div>
            <div class="result-meta">
              <span class="result-type">{{ result.testType }}</span>
              <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>
          <div v-if="result.error" class="result-error">
            <AlertTriangle class="error-icon" />
            <span>{{ result.error }}</span>
          </div>
        </div>
      </div>

      <div v-if="filteredResults.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No test results found</h3>
        <p>Run a test suite to see results here</p>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal || editingSuite" class="modal-overlay" @click="closeModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <TestTube class="modal-title-icon" />
                <h2>{{ editingSuite ? 'Edit Test Suite' : 'Create Test Suite' }}</h2>
              </div>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveTestSuite" class="suite-form">
                <div class="form-group">
                  <label>Test Suite Name</label>
                  <input v-model="suiteForm.name" type="text" required />
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>Application</label>
                    <input v-model="suiteForm.application" type="text" required />
                  </div>
                  <div class="form-group">
                    <label>Team</label>
                    <input v-model="suiteForm.team" type="text" required />
                  </div>
                </div>
                <div class="form-group">
                  <label>Test Types</label>
                  <div class="checkbox-group">
                    <label class="checkbox-label">
                      <input
                        v-model="suiteForm.includeAccessControlTests"
                        type="checkbox"
                      />
                      Access Control Tests
                    </label>
                    <label class="checkbox-label">
                      <input
                        v-model="suiteForm.includeDataBehaviorTests"
                        type="checkbox"
                      />
                      Data Behavior Tests
                    </label>
                    <label class="checkbox-label">
                      <input
                        v-model="suiteForm.includeContractTests"
                        type="checkbox"
                      />
                      Contract Tests
                    </label>
                    <label class="checkbox-label">
                      <input
                        v-model="suiteForm.includeDatasetHealthTests"
                        type="checkbox"
                      />
                      Dataset Health Tests
                    </label>
                  </div>
                </div>
                <div class="form-group">
                  <label>User Roles</label>
                  <input
                    v-model="userRolesInput"
                    type="text"
                    placeholder="admin, researcher, analyst, viewer"
                  />
                  <small>Comma-separated list of roles</small>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">Save Test Suite</button>
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
import { Teleport } from 'vue';
import {
  TestTube,
  Play,
  FileText,
  Edit,
  Plus,
  X,
  AlertTriangle,
  List,
  Clock,
  CheckCircle2
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Tests', icon: TestTube }
];

const router = useRouter();

const activeTab = ref<'suites' | 'execution' | 'results'>('suites');
const searchQuery = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterStatus = ref('');
const showCreateModal = ref(false);
const editingSuite = ref<string | null>(null);

// Test suites data
const testSuites = ref([
  {
    id: '1',
    name: 'Research Tracker API Compliance Tests',
    application: 'research-tracker-api',
    team: 'research-platform',
    status: 'passing',
    lastRun: new Date(Date.now() - 2 * 60 * 60 * 1000),
    testCount: 24,
    score: 95,
    testTypes: ['Access Control', 'Data Behavior', 'Contract']
  },
  {
    id: '2',
    name: 'User Management Service Tests',
    application: 'user-service',
    team: 'platform-team',
    status: 'failing',
    lastRun: new Date(Date.now() - 5 * 60 * 60 * 1000),
    testCount: 18,
    score: 72,
    testTypes: ['Access Control', 'Data Behavior']
  },
  {
    id: '3',
    name: 'Data Pipeline Compliance Tests',
    application: 'data-pipeline',
    team: 'data-engineering',
    status: 'pending',
    lastRun: new Date(Date.now() - 24 * 60 * 60 * 1000),
    testCount: 32,
    score: 88,
    testTypes: ['Data Behavior', 'Dataset Health']
  }
]);

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

const testSuiteOptions = computed(() => {
  return [
    { label: 'All Test Suites', value: '' },
    ...testSuites.value.map(suite => ({ label: suite.name, value: suite.id }))
  ];
});

const resultsStatusOptions = computed(() => [
  { label: 'All Results', value: '' },
  { label: 'Passed', value: 'passed' },
  { label: 'Failed', value: 'failed' }
]);

const resultsTypeOptions = computed(() => [
  { label: 'All Types', value: '' },
  { label: 'Access Control', value: 'access-control' },
  { label: 'Data Behavior', value: 'data-behavior' },
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' }
]);

const filteredTestSuites = computed(() => {
  return testSuites.value.filter(suite => {
    const matchesSearch = suite.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         suite.application.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesApp = !filterApplication.value || suite.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || suite.team === filterTeam.value;
    const matchesStatus = !filterStatus.value || suite.status === filterStatus.value;
    return matchesSearch && matchesApp && matchesTeam && matchesStatus;
  });
});

// Test execution
const currentExecution = ref<any>(null);

// Test results
const testResults = ref([
  {
    id: '1',
    testName: 'PDP Decision: admin accessing report',
    testType: 'access-control',
    passed: true,
    timestamp: new Date(Date.now() - 30 * 60 * 1000),
    error: null
  },
  {
    id: '2',
    testName: 'Query Validation: viewer executing Get all reports',
    testType: 'data-behavior',
    passed: true,
    timestamp: new Date(Date.now() - 35 * 60 * 1000),
    error: null
  },
  {
    id: '3',
    testName: 'Contract: No Raw Email Export',
    testType: 'contract',
    passed: false,
    timestamp: new Date(Date.now() - 40 * 60 * 1000),
    error: 'Raw email export detected in query results'
  }
]);

const resultsFilterSuite = ref('');
const resultsFilterStatus = ref('');
const resultsFilterType = ref('');

const filteredResults = computed(() => {
  return testResults.value.filter(result => {
    const matchesSuite = !resultsFilterSuite.value || true; // Would filter by suite
    const matchesStatus = !resultsFilterStatus.value ||
      (resultsFilterStatus.value === 'passed' && result.passed) ||
      (resultsFilterStatus.value === 'failed' && !result.passed);
    const matchesType = !resultsFilterType.value || result.testType === resultsFilterType.value;
    return matchesSuite && matchesStatus && matchesType;
  });
});

// Form data
const suiteForm = ref({
  name: '',
  application: '',
  team: '',
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeContractTests: false,
  includeDatasetHealthTests: false
});

const userRolesInput = ref('admin, researcher, analyst, viewer');

const tabs = [
  { id: 'suites', label: 'Test Suites', icon: List, badge: testSuites.value.length },
  { id: 'execution', label: 'Execution', icon: Play },
  { id: 'results', label: 'Results', icon: CheckCircle2, badge: testResults.value.length }
];

const viewTestSuite = (id: string) => {
  router.push(`/tests/${id}`);
};

const runTestSuite = async (id: string) => {
  const suite = testSuites.value.find(s => s.id === id);
  if (!suite) return;
  
  activeTab.value = 'execution';
  currentExecution.value = {
    suiteName: suite.name,
    status: 'running',
    progress: 0,
    completed: 0,
    total: suite.testCount,
    logs: [
      { level: 'info', message: `Starting test suite: ${suite.name}`, timestamp: new Date() },
      { level: 'info', message: 'Initializing test environment...', timestamp: new Date() }
    ]
  };

  // Simulate test execution
  simulateTestExecution();
};

const simulateTestExecution = () => {
  if (!currentExecution.value) return;
  
  const interval = setInterval(() => {
    if (!currentExecution.value) {
      clearInterval(interval);
      return;
    }
    
    currentExecution.value.completed++;
    currentExecution.value.progress = Math.round(
      (currentExecution.value.completed / currentExecution.value.total) * 100
    );
    
    currentExecution.value.logs.push({
      level: 'info',
      message: `Running test ${currentExecution.value.completed}/${currentExecution.value.total}...`,
      timestamp: new Date()
    });

    if (currentExecution.value.completed >= currentExecution.value.total) {
      currentExecution.value.status = 'completed';
      currentExecution.value.logs.push({
        level: 'success',
        message: 'All tests completed successfully',
        timestamp: new Date()
      });
      clearInterval(interval);
      
      // Refresh results
      setTimeout(() => {
        activeTab.value = 'results';
      }, 2000);
    }
  }, 500);
};

const editTestSuite = (id: string) => {
  const suite = testSuites.value.find(s => s.id === id);
  if (suite) {
    editingSuite.value = id;
    suiteForm.value = {
      name: suite.name,
      application: suite.application,
      team: suite.team,
      includeAccessControlTests: true,
      includeDataBehaviorTests: true,
      includeContractTests: false,
      includeDatasetHealthTests: false
    };
    showCreateModal.value = true;
  }
};

const viewResults = (id: string) => {
  activeTab.value = 'results';
  resultsFilterSuite.value = id;
};

const viewResultDetails = (id: string) => {
  router.push(`/tests/results/${id}`);
};

const saveTestSuite = () => {
  if (editingSuite.value) {
    // Update existing
    const index = testSuites.value.findIndex(s => s.id === editingSuite.value);
    if (index !== -1) {
      testSuites.value[index] = {
        ...testSuites.value[index],
        ...suiteForm.value,
        userRoles: userRolesInput.value.split(',').map(r => r.trim())
      };
    }
  } else {
    // Create new
    testSuites.value.push({
      id: String(testSuites.value.length + 1),
      ...suiteForm.value,
      status: 'pending',
      lastRun: new Date(),
      testCount: 0,
      score: 0,
      testTypes: []
    });
  }
  closeModal();
};

const closeModal = () => {
  showCreateModal.value = false;
  editingSuite.value = null;
  suiteForm.value = {
    name: '',
    application: '',
    team: '',
    includeAccessControlTests: true,
    includeDataBehaviorTests: true,
    includeContractTests: false,
    includeDatasetHealthTests: false
  };
  userRolesInput.value = 'admin, researcher, analyst, viewer';
};

const formatDate = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const formatTime = (date: Date): string => {
  return date.toLocaleTimeString();
};

const formatRelativeTime = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};
</script>

<style scoped>
.tests-page {
  width: 100%;
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
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 32px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.tab-button:hover {
  color: #4facfe;
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-badge {
  padding: 2px 8px;
  border-radius: 10px;
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 600;
}

.tab-content {
  min-height: 400px;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.test-suites-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
  gap: 24px;
}

.test-suite-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.test-suite-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.suite-header {
  margin-bottom: 20px;
}

.suite-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.suite-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.suite-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-passing {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failing {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-pending {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.suite-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.suite-stats {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.stat {
  display: flex;
  flex-direction: column;
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

.stat-value.score {
  font-size: 1rem;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.suite-types {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}

.test-type-badge {
  padding: 4px 10px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}

.suite-actions {
  display: flex;
  gap: 8px;
}

.action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  flex: 1;
  justify-content: center;
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.run-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.execution-view {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.execution-header {
  margin-bottom: 24px;
}

.execution-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.execution-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
  display: inline-block;
}

.status-running {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.execution-progress {
  margin-top: 16px;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
  margin-bottom: 8px;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.progress-text {
  font-size: 0.875rem;
  color: #a0aec0;
}

.execution-log {
  max-height: 400px;
  overflow-y: auto;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  padding: 16px;
}

.log-entry {
  display: flex;
  gap: 12px;
  padding: 8px 0;
  font-size: 0.875rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.log-entry:last-child {
  border-bottom: none;
}

.log-time {
  color: #718096;
  font-family: monospace;
  min-width: 80px;
}

.log-message {
  color: #a0aec0;
}

.log-info .log-message {
  color: #4facfe;
}

.log-success .log-message {
  color: #22c55e;
}

.log-error .log-message {
  color: #fc8181;
}

.results-filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.result-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.2s;
}

.result-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateX(4px);
}

.result-header {
  margin-bottom: 12px;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.result-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.result-status {
  padding: 4px 10px;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.result-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.result-type {
  text-transform: capitalize;
}

.result-error {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 6px;
  color: #fc8181;
  font-size: 0.875rem;
}

.error-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
  opacity: 0.5;
}

.empty-state h3 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 8px;
}

.empty-state p {
  font-size: 1rem;
  color: #a0aec0;
  margin-bottom: 24px;
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.suite-form {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-group label {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.form-group input,
.form-group select {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group small {
  font-size: 0.75rem;
  color: #718096;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #a0aec0;
}

.checkbox-label input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 8px;
}

.btn-secondary {
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
