<template>
  <div class="environments-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Ephemeral Environments</h1>
          <p class="page-description">Manage and monitor ephemeral environments for PR testing</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create Environment
        </button>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search environments..."
        class="search-input"
      />
      <Dropdown
        v-model="filterPR"
        :options="prOptions"
        placeholder="All PRs"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterBranch"
        :options="branchOptions"
        placeholder="All Branches"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <!-- Environments Grid -->
    <div class="environments-grid">
      <div
        v-for="env in filteredEnvironments"
        :key="env.id"
        class="environment-card"
        @click="viewEnvironmentDetails(env.id)"
      >
        <div class="env-header">
          <div class="env-title-row">
            <h3 class="env-name">{{ env.name }}</h3>
            <span class="env-status" :class="`status-${env.status}`">
              {{ env.status }}
            </span>
          </div>
          <div class="env-meta">
            <span class="env-pr">PR #{{ env.prNumber }}</span>
            <span class="env-branch">{{ env.branch }}</span>
            <span class="env-time">{{ formatRelativeTime(env.createdAt) }}</span>
          </div>
        </div>

        <div class="env-details">
          <div class="detail-item">
            <span class="detail-label">Created:</span>
            <span class="detail-value">{{ formatDate(env.createdAt) }}</span>
          </div>
          <div class="detail-item" v-if="env.expiresAt">
            <span class="detail-label">Expires:</span>
            <span class="detail-value">{{ formatDate(env.expiresAt) }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Tests:</span>
            <span class="detail-value">{{ env.testCount || 0 }} run</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Compliance Score:</span>
            <span class="detail-value score" :class="getScoreClass(env.complianceScore)">
              {{ env.complianceScore || 0 }}%
            </span>
          </div>
        </div>

        <div class="env-health" v-if="env.health">
          <div class="health-indicator">
            <div class="health-label">Health:</div>
            <div class="health-bars">
              <div
                class="health-bar"
                :class="`health-${env.health.status}`"
                :style="{ width: `${env.health.score}%` }"
              ></div>
            </div>
            <span class="health-score">{{ env.health.score }}%</span>
          </div>
        </div>

        <div class="env-resources" v-if="env.resources">
          <div class="resource-item">
            <span class="resource-label">CPU:</span>
            <span class="resource-value">{{ env.resources.cpu }}%</span>
          </div>
          <div class="resource-item">
            <span class="resource-label">Memory:</span>
            <span class="resource-value">{{ env.resources.memory }}%</span>
          </div>
          <div class="resource-item">
            <span class="resource-label">Storage:</span>
            <span class="resource-value">{{ env.resources.storage }}%</span>
          </div>
        </div>

        <div class="env-actions">
          <button @click.stop="viewEnvironmentDetails(env.id)" class="action-btn view-btn">
            <Eye class="action-icon" />
            View
          </button>
          <button @click.stop="viewTestResults(env.id)" class="action-btn results-btn">
            <FileText class="action-icon" />
            Tests
          </button>
          <button @click.stop="cleanupEnvironment(env.id)" class="action-btn cleanup-btn" v-if="env.status === 'active'">
            <Trash2 class="action-icon" />
            Cleanup
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredEnvironments.length === 0" class="empty-state">
      <Server class="empty-icon" />
      <h3>No ephemeral environments found</h3>
      <p>Create an environment for a PR to get started</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Create Environment
      </button>
    </div>

    <!-- Create Environment Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal" class="modal-overlay" @click="closeCreateModal">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Server class="modal-title-icon" />
                <h2>Create Ephemeral Environment</h2>
              </div>
              <button @click="closeCreateModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="createEnvironment" class="env-form">
                <div class="form-group">
                  <label>PR Number *</label>
                  <input v-model="createForm.prNumber" type="number" required />
                </div>
                <div class="form-group">
                  <label>Branch Name *</label>
                  <input v-model="createForm.branch" type="text" required placeholder="feature/new-feature" />
                </div>
                <div class="form-group">
                  <label>Environment Name</label>
                  <input v-model="createForm.name" type="text" :placeholder="`pr-${createForm.prNumber || 'XXX'}`" />
                  <small>Auto-generated if left empty</small>
                </div>
                <div class="form-row">
                  <div class="form-group">
                    <label>TTL (Time to Live)</label>
                    <select v-model="createForm.ttl">
                      <option value="1h">1 Hour</option>
                      <option value="6h">6 Hours</option>
                      <option value="12h">12 Hours</option>
                      <option value="24h">24 Hours</option>
                      <option value="48h">48 Hours</option>
                    </select>
                  </div>
                  <div class="form-group">
                    <label>Resource Limit</label>
                    <select v-model="createForm.resourceLimit">
                      <option value="small">Small (1 CPU, 2GB RAM)</option>
                      <option value="medium">Medium (2 CPU, 4GB RAM)</option>
                      <option value="large">Large (4 CPU, 8GB RAM)</option>
                    </select>
                  </div>
                </div>
                <div class="form-group">
                  <label>Run Tests Automatically</label>
                  <div class="checkbox-group">
                    <label class="checkbox-label">
                      <input v-model="createForm.runTests" type="checkbox" />
                      Run compliance tests after environment creation
                    </label>
                  </div>
                </div>
                <div class="form-actions">
                  <button type="button" @click="closeCreateModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary">Create Environment</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Environment Detail Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showDetailModal && selectedEnvironment" class="modal-overlay" @click="closeDetailModal">
          <div class="modal-content large-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Server class="modal-title-icon" />
                <div>
                  <h2>{{ selectedEnvironment.name }}</h2>
                  <p class="modal-subtitle">PR #{{ selectedEnvironment.prNumber }} • {{ selectedEnvironment.branch }}</p>
                </div>
              </div>
              <button @click="closeDetailModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div class="detail-sections">
                <div class="detail-section">
                  <h3 class="section-title">Environment Status</h3>
                  <div class="status-grid">
                    <div class="status-item">
                      <span class="status-label">Status:</span>
                      <span class="status-value" :class="`status-${selectedEnvironment.status}`">
                        {{ selectedEnvironment.status }}
                      </span>
                    </div>
                    <div class="status-item">
                      <span class="status-label">Created:</span>
                      <span class="status-value">{{ formatDate(selectedEnvironment.createdAt) }}</span>
                    </div>
                    <div class="status-item" v-if="selectedEnvironment.expiresAt">
                      <span class="status-label">Expires:</span>
                      <span class="status-value">{{ formatDate(selectedEnvironment.expiresAt) }}</span>
                    </div>
                    <div class="status-item">
                      <span class="status-label">Compliance Score:</span>
                      <span class="status-value score" :class="getScoreClass(selectedEnvironment.complianceScore)">
                        {{ selectedEnvironment.complianceScore || 0 }}%
                      </span>
                    </div>
                  </div>
                </div>

                <div class="detail-section" v-if="selectedEnvironment.health">
                  <h3 class="section-title">Environment Health</h3>
                  <div class="health-section">
                    <div class="health-indicator-large">
                      <div class="health-bars-large">
                        <div
                          class="health-bar-large"
                          :class="`health-${selectedEnvironment.health.status}`"
                          :style="{ width: `${selectedEnvironment.health.score}%` }"
                        ></div>
                      </div>
                      <div class="health-info">
                        <span class="health-status" :class="`status-${selectedEnvironment.health.status}`">
                          {{ selectedEnvironment.health.status }}
                        </span>
                        <span class="health-score">{{ selectedEnvironment.health.score }}%</span>
                      </div>
                    </div>
                    <div v-if="selectedEnvironment.health.issues && selectedEnvironment.health.issues.length > 0" class="health-issues">
                      <div v-for="(issue, index) in selectedEnvironment.health.issues" :key="index" class="health-issue">
                        <AlertTriangle class="issue-icon" />
                        <span>{{ issue }}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="detail-section" v-if="selectedEnvironment.resources">
                  <h3 class="section-title">Resource Usage</h3>
                  <div class="resources-grid">
                    <div class="resource-card">
                      <div class="resource-header">
                        <span class="resource-name">CPU</span>
                        <span class="resource-percent">{{ selectedEnvironment.resources.cpu }}%</span>
                      </div>
                      <div class="resource-bar">
                        <div
                          class="resource-fill"
                          :class="getResourceClass(selectedEnvironment.resources.cpu)"
                          :style="{ width: `${selectedEnvironment.resources.cpu}%` }"
                        ></div>
                      </div>
                    </div>
                    <div class="resource-card">
                      <div class="resource-header">
                        <span class="resource-name">Memory</span>
                        <span class="resource-percent">{{ selectedEnvironment.resources.memory }}%</span>
                      </div>
                      <div class="resource-bar">
                        <div
                          class="resource-fill"
                          :class="getResourceClass(selectedEnvironment.resources.memory)"
                          :style="{ width: `${selectedEnvironment.resources.memory}%` }"
                        ></div>
                      </div>
                    </div>
                    <div class="resource-card">
                      <div class="resource-header">
                        <span class="resource-name">Storage</span>
                        <span class="resource-percent">{{ selectedEnvironment.resources.storage }}%</span>
                      </div>
                      <div class="resource-bar">
                        <div
                          class="resource-fill"
                          :class="getResourceClass(selectedEnvironment.resources.storage)"
                          :style="{ width: `${selectedEnvironment.resources.storage}%` }"
                        ></div>
                      </div>
                    </div>
                  </div>
                </div>

                <div class="detail-section" v-if="selectedEnvironment.testExecution">
                  <h3 class="section-title">Test Execution Status</h3>
                  <div class="test-execution">
                    <div class="test-status-row">
                      <span class="test-label">Status:</span>
                      <span class="test-value" :class="`status-${selectedEnvironment.testExecution.status}`">
                        {{ selectedEnvironment.testExecution.status }}
                      </span>
                    </div>
                    <div class="test-status-row" v-if="selectedEnvironment.testExecution.progress !== undefined">
                      <span class="test-label">Progress:</span>
                      <div class="test-progress">
                        <div class="test-progress-bar">
                          <div
                            class="test-progress-fill"
                            :style="{ width: `${selectedEnvironment.testExecution.progress}%` }"
                          ></div>
                        </div>
                        <span class="test-progress-text">{{ selectedEnvironment.testExecution.progress }}%</span>
                      </div>
                    </div>
                    <div class="test-status-row">
                      <span class="test-label">Tests Run:</span>
                      <span class="test-value">{{ selectedEnvironment.testExecution.testsRun || 0 }} / {{ selectedEnvironment.testExecution.testsTotal || 0 }}</span>
                    </div>
                    <div class="test-status-row">
                      <span class="test-label">Passed:</span>
                      <span class="test-value passed">{{ selectedEnvironment.testExecution.testsPassed || 0 }}</span>
                    </div>
                    <div class="test-status-row">
                      <span class="test-label">Failed:</span>
                      <span class="test-value failed">{{ selectedEnvironment.testExecution.testsFailed || 0 }}</span>
                    </div>
                  </div>
                </div>

                <div class="detail-section">
                  <h3 class="section-title">Actions</h3>
                  <div class="action-buttons">
                    <button @click="viewTestResults(selectedEnvironment.id)" class="btn-secondary">
                      <FileText class="btn-icon" />
                      View Test Results
                    </button>
                    <button @click="runTests(selectedEnvironment.id)" class="btn-secondary" v-if="selectedEnvironment.status === 'active'">
                      <Play class="btn-icon" />
                      Run Tests
                    </button>
                    <button @click="cleanupEnvironment(selectedEnvironment.id)" class="btn-danger" v-if="selectedEnvironment.status === 'active'">
                      <Trash2 class="btn-icon" />
                      Cleanup Environment
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { Teleport } from 'vue';
import {
  Server,
  Plus,
  X,
  Eye,
  FileText,
  Trash2,
  Play,
  AlertTriangle
} from 'lucide-vue-next';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Ephemeral Environments', icon: Server }
];

const searchQuery = ref('');
const filterPR = ref('');
const filterBranch = ref('');
const filterStatus = ref('');
const showCreateModal = ref(false);
const showDetailModal = ref(false);
const selectedEnvironment = ref<any>(null);

// Environments data
const environments = ref([
  {
    id: '1',
    name: 'pr-123-feature-auth',
    prNumber: 123,
    branch: 'feature/auth-improvements',
    status: 'active',
    createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() + 22 * 60 * 60 * 1000),
    testCount: 5,
    complianceScore: 92,
    health: {
      status: 'healthy',
      score: 95,
      issues: []
    },
    resources: {
      cpu: 45,
      memory: 62,
      storage: 38
    },
    testExecution: {
      status: 'completed',
      progress: 100,
      testsRun: 24,
      testsTotal: 24,
      testsPassed: 22,
      testsFailed: 2
    }
  },
  {
    id: '2',
    name: 'pr-124-bugfix-api',
    prNumber: 124,
    branch: 'bugfix/api-error-handling',
    status: 'active',
    createdAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() + 19 * 60 * 60 * 1000),
    testCount: 3,
    complianceScore: 78,
    health: {
      status: 'warning',
      score: 72,
      issues: ['High memory usage detected', 'Storage approaching limit']
    },
    resources: {
      cpu: 78,
      memory: 89,
      storage: 85
    },
    testExecution: {
      status: 'running',
      progress: 65,
      testsRun: 16,
      testsTotal: 24,
      testsPassed: 14,
      testsFailed: 2
    }
  },
  {
    id: '3',
    name: 'pr-122-feature-dashboard',
    prNumber: 122,
    branch: 'feature/dashboard-redesign',
    status: 'completed',
    createdAt: new Date(Date.now() - 48 * 60 * 60 * 1000),
    expiresAt: new Date(Date.now() - 24 * 60 * 60 * 1000),
    testCount: 8,
    complianceScore: 88,
    health: {
      status: 'healthy',
      score: 90
    },
    resources: {
      cpu: 0,
      memory: 0,
      storage: 0
    },
    testExecution: {
      status: 'completed',
      progress: 100,
      testsRun: 32,
      testsTotal: 32,
      testsPassed: 28,
      testsFailed: 4
    }
  },
  {
    id: '4',
    name: 'pr-121-hotfix-security',
    prNumber: 121,
    branch: 'hotfix/security-patch',
    status: 'failed',
    createdAt: new Date(Date.now() - 12 * 60 * 60 * 1000),
    expiresAt: null,
    testCount: 2,
    complianceScore: 45,
    health: {
      status: 'critical',
      score: 35,
      issues: ['Environment failed to start', 'Resource allocation error']
    },
    resources: {
      cpu: 0,
      memory: 0,
      storage: 0
    },
    testExecution: {
      status: 'failed',
      progress: 0,
      testsRun: 0,
      testsTotal: 20,
      testsPassed: 0,
      testsFailed: 0
    }
  }
]);

const prOptions = computed(() => {
  const prs = [...new Set(environments.value.map(e => e.prNumber))];
  return [
    { label: 'All PRs', value: '' },
    ...prs.map(pr => ({ label: `PR #${pr}`, value: String(pr) }))
  ];
});

const branchOptions = computed(() => {
  const branches = [...new Set(environments.value.map(e => e.branch))];
  return [
    { label: 'All Branches', value: '' },
    ...branches.map(branch => ({ label: branch, value: branch }))
  ];
});

const statusOptions = computed(() => [
  { label: 'All Statuses', value: '' },
  { label: 'Active', value: 'active' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' }
]);

const filteredEnvironments = computed(() => {
  return environments.value.filter(env => {
    const matchesSearch = env.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                         env.branch.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesPR = !filterPR.value || String(env.prNumber) === filterPR.value;
    const matchesBranch = !filterBranch.value || env.branch === filterBranch.value;
    const matchesStatus = !filterStatus.value || env.status === filterStatus.value;
    return matchesSearch && matchesPR && matchesBranch && matchesStatus;
  });
});

const createForm = ref({
  prNumber: '',
  branch: '',
  name: '',
  ttl: '24h',
  resourceLimit: 'medium',
  runTests: true
});

function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffMs / 86400000);
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

function getScoreClass(score: number): string {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
}

function getResourceClass(percent: number): string {
  if (percent >= 80) return 'resource-high';
  if (percent >= 60) return 'resource-medium';
  return 'resource-low';
}

function viewEnvironmentDetails(id: string) {
  const env = environments.value.find(e => e.id === id);
  if (env) {
    selectedEnvironment.value = env;
    showDetailModal.value = true;
  }
}

function closeDetailModal() {
  showDetailModal.value = false;
  selectedEnvironment.value = null;
}

function viewTestResults(id: string) {
  // Navigate to test results for this environment
  console.log('View test results for environment:', id);
  // In a real app, this would navigate to a test results page filtered by environment
}

function runTests(id: string) {
  const env = environments.value.find(e => e.id === id);
  if (env && env.status === 'active') {
    // Simulate running tests
    env.testExecution = {
      status: 'running',
      progress: 0,
      testsRun: 0,
      testsTotal: 24,
      testsPassed: 0,
      testsFailed: 0
    };
    // Simulate test progress
    const interval = setInterval(() => {
      if (env.testExecution && env.testExecution.progress < 100) {
        env.testExecution.progress += 10;
        env.testExecution.testsRun = Math.floor((env.testExecution.progress / 100) * env.testExecution.testsTotal);
        env.testExecution.testsPassed = Math.floor(env.testExecution.testsRun * 0.9);
        env.testExecution.testsFailed = env.testExecution.testsRun - env.testExecution.testsPassed;
      } else {
        if (env.testExecution) {
          env.testExecution.status = 'completed';
          env.testExecution.progress = 100;
        }
        clearInterval(interval);
      }
    }, 500);
  }
}

function cleanupEnvironment(id: string) {
  if (confirm('Are you sure you want to cleanup this environment? This action cannot be undone.')) {
    const env = environments.value.find(e => e.id === id);
    if (env) {
      env.status = 'completed';
      env.resources = { cpu: 0, memory: 0, storage: 0 };
    }
  }
}

function createEnvironment() {
  const newEnv = {
    id: String(environments.value.length + 1),
    name: createForm.value.name || `pr-${createForm.value.prNumber}-${createForm.value.branch.split('/').pop()}`,
    prNumber: parseInt(createForm.value.prNumber),
    branch: createForm.value.branch,
    status: 'active',
    createdAt: new Date(),
    expiresAt: calculateExpiry(createForm.value.ttl),
    testCount: 0,
    complianceScore: 0,
    health: {
      status: 'healthy',
      score: 100,
      issues: []
    },
    resources: {
      cpu: 0,
      memory: 0,
      storage: 0
    },
    testExecution: {
      status: 'pending',
      progress: 0,
      testsRun: 0,
      testsTotal: 0,
      testsPassed: 0,
      testsFailed: 0
    }
  };
  
  environments.value.unshift(newEnv);
  
  if (createForm.value.runTests) {
    setTimeout(() => runTests(newEnv.id), 2000);
  }
  
  closeCreateModal();
}

function calculateExpiry(ttl: string): Date {
  const now = new Date();
  const hours = parseInt(ttl.replace('h', ''));
  return new Date(now.getTime() + hours * 60 * 60 * 1000);
}

function closeCreateModal() {
  showCreateModal.value = false;
  createForm.value = {
    prNumber: '',
    branch: '',
    name: '',
    ttl: '24h',
    resourceLimit: 'medium',
    runTests: true
  };
}
</script>

<style scoped>
.environments-page {
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

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1;
  min-width: 200px;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.filter-dropdown {
  min-width: 150px;
}

.environments-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.environment-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.environment-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.env-header {
  margin-bottom: 20px;
}

.env-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.env-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.env-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-healthy {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-warning {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.env-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.env-pr {
  font-weight: 600;
  color: #4facfe;
}

.env-details {
  margin-bottom: 16px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  padding: 8px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.detail-item:last-child {
  border-bottom: none;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
}

.detail-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.detail-value.score {
  font-weight: 600;
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

.env-health {
  margin-bottom: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.health-indicator {
  display: flex;
  align-items: center;
  gap: 12px;
}

.health-label {
  font-size: 0.875rem;
  color: #718096;
  min-width: 60px;
}

.health-bars {
  flex: 1;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.health-bar {
  height: 100%;
  transition: width 0.3s;
}

.health-healthy {
  background: linear-gradient(90deg, #22c55e 0%, #16a34a 100%);
}

.health-warning {
  background: linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%);
}

.health-critical {
  background: linear-gradient(90deg, #fc8181 0%, #ef4444 100%);
}

.health-score {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
  min-width: 40px;
  text-align: right;
}

.env-resources {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.resource-item {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.resource-label {
  font-size: 0.75rem;
  color: #718096;
}

.resource-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.env-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
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

.cleanup-btn {
  border-color: rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.cleanup-btn:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
  color: #fc8181;
}

.action-icon {
  width: 16px;
  height: 16px;
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

.large-modal {
  max-width: 900px;
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
  align-items: flex-start;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 4px;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.modal-subtitle {
  font-size: 0.875rem;
  color: #a0aec0;
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

.detail-sections {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.detail-section {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.status-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 16px;
}

.status-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.status-label {
  font-size: 0.75rem;
  color: #718096;
}

.status-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.health-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.health-indicator-large {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.health-bars-large {
  width: 100%;
  height: 12px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 6px;
  overflow: hidden;
}

.health-bar-large {
  height: 100%;
  transition: width 0.3s;
}

.health-info {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.health-status {
  padding: 4px 12px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
}

.health-issues {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.health-issue {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px;
  background: rgba(252, 129, 129, 0.1);
  border-left: 3px solid #fc8181;
  border-radius: 4px;
  color: #fc8181;
  font-size: 0.875rem;
}

.issue-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.resources-grid {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.resource-card {
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.resource-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.resource-name {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
}

.resource-percent {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
}

.resource-bar {
  width: 100%;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.resource-fill {
  height: 100%;
  transition: width 0.3s;
}

.resource-low {
  background: linear-gradient(90deg, #22c55e 0%, #16a34a 100%);
}

.resource-medium {
  background: linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%);
}

.resource-high {
  background: linear-gradient(90deg, #fc8181 0%, #ef4444 100%);
}

.test-execution {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.test-status-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.test-label {
  font-size: 0.875rem;
  color: #718096;
}

.test-value {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
}

.test-value.passed {
  color: #22c55e;
}

.test-value.failed {
  color: #fc8181;
}

.test-progress {
  display: flex;
  align-items: center;
  gap: 12px;
  flex: 1;
}

.test-progress-bar {
  flex: 1;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.test-progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.test-progress-text {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
  min-width: 40px;
  text-align: right;
}

.action-buttons {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
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

.btn-danger {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(252, 129, 129, 0.3);
  border-radius: 12px;
  color: #fc8181;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-danger:hover {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.env-form {
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

