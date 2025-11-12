<template>
  <div class="cicd-integration-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">CI/CD Integration</h1>
          <p class="page-description">Configure and monitor compliance testing in your CI/CD pipelines</p>
        </div>
        <div class="header-actions">
          <button @click="showConfigModal = true" class="btn-primary">
            <Settings class="btn-icon" />
            Configure
          </button>
        </div>
      </div>
    </div>

    <!-- Platform Tabs -->
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

    <!-- GitHub Actions Tab -->
    <div v-if="activeTab === 'github'" class="tab-content">
      <div class="config-section">
        <div class="section-header">
          <h2>GitHub Actions Configuration</h2>
          <button @click="editGitHubConfig" class="btn-secondary">
            <Edit class="btn-icon" />
            Edit Configuration
          </button>
        </div>

        <div v-if="githubConfig" class="config-display">
          <div class="config-item">
            <span class="config-label">Status:</span>
            <span class="config-value" :class="githubConfig.enabled ? 'enabled' : 'disabled'">
              {{ githubConfig.enabled ? 'Enabled' : 'Disabled' }}
            </span>
          </div>
          <div class="config-item">
            <span class="config-label">Repository:</span>
            <span class="config-value">{{ githubConfig.repository || 'Not configured' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Workflow File:</span>
            <span class="config-value">{{ githubConfig.workflowFile || '.github/workflows/compliance-tests.yml' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Compliance Threshold:</span>
            <span class="config-value">{{ githubConfig.complianceThreshold }}%</span>
          </div>
          <div class="config-item">
            <span class="config-label">Block Merges:</span>
            <span class="config-value">{{ githubConfig.blockMerges ? 'Yes' : 'No' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">PR Comments:</span>
            <span class="config-value">{{ githubConfig.prComments ? 'Enabled' : 'Disabled' }}</span>
          </div>
        </div>
        <div v-else class="empty-config">
          <p>GitHub Actions integration not configured</p>
          <button @click="editGitHubConfig" class="btn-primary">
            Configure GitHub Actions
          </button>
        </div>
      </div>

      <!-- Recent Runs -->
      <div class="runs-section">
        <div class="section-header">
          <h2>Recent Runs</h2>
          <button @click="refreshRuns" class="btn-secondary" :disabled="isLoading">
            <RefreshCw class="btn-icon" :class="{ spinning: isLoading }" />
            Refresh
          </button>
        </div>

        <div class="runs-list">
          <div
            v-for="run in githubRuns"
            :key="run.id"
            class="run-card"
            @click="viewRunDetails(run.id)"
          >
            <div class="run-header">
              <div class="run-title-row">
                <h3 class="run-name">{{ run.name }}</h3>
                <span class="run-status" :class="`status-${run.status}`">
                  {{ run.status }}
                </span>
              </div>
              <p class="run-meta">
                PR #{{ run.prNumber }} • {{ formatDate(run.startedAt) }}
              </p>
            </div>

            <div class="run-summary">
              <div class="summary-item">
                <CheckCircle2 v-if="run.compliancePassed" class="summary-icon passed" />
                <X v-else class="summary-icon failed" />
                <span>Compliance: {{ run.complianceScore }}%</span>
              </div>
              <div class="summary-item">
                <Clock class="summary-icon" />
                <span>{{ run.duration }}s</span>
              </div>
              <div class="summary-item" v-if="run.blocked">
                <AlertTriangle class="summary-icon warning" />
                <span>Merge Blocked</span>
              </div>
            </div>
          </div>
        </div>

        <div v-if="githubRuns.length === 0 && !isLoading" class="empty-state">
          <GitBranch class="empty-icon" />
          <h3>No runs found</h3>
          <p>GitHub Actions runs will appear here once configured</p>
        </div>
      </div>
    </div>

    <!-- Jenkins Tab -->
    <div v-if="activeTab === 'jenkins'" class="tab-content">
      <div class="config-section">
        <div class="section-header">
          <h2>Jenkins Configuration</h2>
          <button @click="editJenkinsConfig" class="btn-secondary">
            <Edit class="btn-icon" />
            Edit Configuration
          </button>
        </div>

        <div v-if="jenkinsConfig" class="config-display">
          <div class="config-item">
            <span class="config-label">Status:</span>
            <span class="config-value" :class="jenkinsConfig.enabled ? 'enabled' : 'disabled'">
              {{ jenkinsConfig.enabled ? 'Enabled' : 'Disabled' }}
            </span>
          </div>
          <div class="config-item">
            <span class="config-label">Jenkins URL:</span>
            <span class="config-value">{{ jenkinsConfig.url || 'Not configured' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Job Name:</span>
            <span class="config-value">{{ jenkinsConfig.jobName || 'Not configured' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Compliance Threshold:</span>
            <span class="config-value">{{ jenkinsConfig.complianceThreshold }}%</span>
          </div>
          <div class="config-item">
            <span class="config-label">Block Builds:</span>
            <span class="config-value">{{ jenkinsConfig.blockBuilds ? 'Yes' : 'No' }}</span>
          </div>
          <div class="config-item">
            <span class="config-label">Pipeline Script:</span>
            <span class="config-value">{{ jenkinsConfig.pipelineScript ? 'Configured' : 'Not configured' }}</span>
          </div>
        </div>
        <div v-else class="empty-config">
          <p>Jenkins integration not configured</p>
          <button @click="editJenkinsConfig" class="btn-primary">
            Configure Jenkins
          </button>
        </div>
      </div>

      <!-- Recent Builds -->
      <div class="runs-section">
        <div class="section-header">
          <h2>Recent Builds</h2>
          <button @click="refreshRuns" class="btn-secondary" :disabled="isLoading">
            <RefreshCw class="btn-icon" :class="{ spinning: isLoading }" />
            Refresh
          </button>
        </div>

        <div class="runs-list">
          <div
            v-for="build in jenkinsBuilds"
            :key="build.id"
            class="run-card"
            @click="viewRunDetails(build.id)"
          >
            <div class="run-header">
              <div class="run-title-row">
                <h3 class="run-name">{{ build.name }}</h3>
                <span class="run-status" :class="`status-${build.status}`">
                  {{ build.status }}
                </span>
              </div>
              <p class="run-meta">
                Build #{{ build.buildNumber }} • {{ formatDate(build.startedAt) }}
              </p>
            </div>

            <div class="run-summary">
              <div class="summary-item">
                <CheckCircle2 v-if="build.compliancePassed" class="summary-icon passed" />
                <X v-else class="summary-icon failed" />
                <span>Compliance: {{ build.complianceScore }}%</span>
              </div>
              <div class="summary-item">
                <Clock class="summary-icon" />
                <span>{{ build.duration }}s</span>
              </div>
              <div class="summary-item" v-if="build.blocked">
                <AlertTriangle class="summary-icon warning" />
                <span>Build Blocked</span>
              </div>
            </div>
          </div>
        </div>

        <div v-if="jenkinsBuilds.length === 0 && !isLoading" class="empty-state">
          <Settings class="empty-icon" />
          <h3>No builds found</h3>
          <p>Jenkins builds will appear here once configured</p>
        </div>
      </div>
    </div>

    <!-- Settings Tab -->
    <div v-if="activeTab === 'settings'" class="tab-content">
      <div class="settings-section">
        <h2>Global Settings</h2>

        <div class="settings-group">
          <h3>Compliance Thresholds</h3>
          <div class="form-group">
            <label>Minimum Compliance Score (%)</label>
            <input
              v-model.number="globalSettings.minComplianceScore"
              type="number"
              min="0"
              max="100"
              class="form-input"
            />
            <p class="form-help">PRs/builds below this score will be blocked</p>
          </div>
        </div>

        <div class="settings-group">
          <h3>Merge Blocking Rules</h3>
          <label class="checkbox-option">
            <input
              v-model="globalSettings.blockOnFailure"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Block merge on any test failure</span>
          </label>
          <label class="checkbox-option">
            <input
              v-model="globalSettings.blockOnThreshold"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Block merge if score below threshold</span>
          </label>
          <label class="checkbox-option">
            <input
              v-model="globalSettings.requireApproval"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Require manual approval for blocked PRs</span>
          </label>
        </div>

        <div class="settings-group">
          <h3>Notifications</h3>
          <label class="checkbox-option">
            <input
              v-model="globalSettings.notifyOnFailure"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Notify on test failures</span>
          </label>
          <label class="checkbox-option">
            <input
              v-model="globalSettings.notifyOnBlock"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Notify when merge is blocked</span>
          </label>
          <div class="form-group">
            <label>Notification Channels</label>
            <div class="checkbox-group">
              <label class="checkbox-option">
                <input
                  v-model="globalSettings.notificationChannels"
                  type="checkbox"
                  value="email"
                  class="checkbox-input"
                />
                <span>Email</span>
              </label>
              <label class="checkbox-option">
                <input
                  v-model="globalSettings.notificationChannels"
                  type="checkbox"
                  value="slack"
                  class="checkbox-input"
                />
                <span>Slack</span>
              </label>
              <label class="checkbox-option">
                <input
                  v-model="globalSettings.notificationChannels"
                  type="checkbox"
                  value="webhook"
                  class="checkbox-input"
                />
                <span>Webhook</span>
              </label>
            </div>
          </div>
        </div>

        <div class="settings-actions">
          <button @click="saveSettings" class="btn-primary" :disabled="isSaving">
            <Save v-if="!isSaving" class="btn-icon" />
            <Loader2 v-else class="btn-icon spinning" />
            {{ isSaving ? 'Saving...' : 'Save Settings' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Configuration Modal -->
    <CICDConfigModal
      v-model:isOpen="showConfigModal"
      :platform="editingPlatform"
      :config="editingConfig"
      @saved="handleConfigSaved"
    />

    <!-- Run Details Modal -->
    <RunDetailsModal
      v-model:isOpen="showRunModal"
      :run="selectedRun"
      :platform="activeTab"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  Settings,
  GitBranch,
  Edit,
  RefreshCw,
  CheckCircle2,
  X,
  Clock,
  AlertTriangle,
  Save,
  Loader2
} from 'lucide-vue-next';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';
import CICDConfigModal from '../components/CICDConfigModal.vue';
import RunDetailsModal from '../components/RunDetailsModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'CI/CD Integration' }
];

const activeTab = ref('github');
const isLoading = ref(false);
const isSaving = ref(false);
const showConfigModal = ref(false);
const showRunModal = ref(false);
const editingPlatform = ref<'github' | 'jenkins' | null>(null);
const editingConfig = ref<any>(null);
const selectedRun = ref<any>(null);

const tabs = [
  { id: 'github', label: 'GitHub Actions', icon: GitBranch, badge: null },
  { id: 'jenkins', label: 'Jenkins', icon: Settings, badge: null },
  { id: 'settings', label: 'Settings', icon: Settings, badge: null },
];

const githubConfig = ref<any>(null);
const jenkinsConfig = ref<any>(null);
const githubRuns = ref<any[]>([]);
const jenkinsBuilds = ref<any[]>([]);
const globalSettings = ref({
  minComplianceScore: 100,
  blockOnFailure: true,
  blockOnThreshold: true,
  requireApproval: false,
  notifyOnFailure: true,
  notifyOnBlock: true,
  notificationChannels: [] as string[],
});

const loadConfigs = async () => {
  try {
    const [githubRes, jenkinsRes] = await Promise.all([
      axios.get('/api/cicd/github/config').catch(() => ({ data: null })),
      axios.get('/api/cicd/jenkins/config').catch(() => ({ data: null })),
    ]);
    githubConfig.value = githubRes.data;
    jenkinsConfig.value = jenkinsRes.data;
  } catch (error) {
    console.error('Failed to load configs:', error);
  }
};

const loadRuns = async () => {
  isLoading.value = true;
  try {
    const [githubRes, jenkinsRes] = await Promise.all([
      axios.get('/api/cicd/github/runs').catch(() => ({ data: [] })),
      axios.get('/api/cicd/jenkins/builds').catch(() => ({ data: [] })),
    ]);
    githubRuns.value = githubRes.data.map((r: any) => ({
      ...r,
      startedAt: new Date(r.startedAt),
    }));
    jenkinsBuilds.value = jenkinsRes.data.map((b: any) => ({
      ...b,
      startedAt: new Date(b.startedAt),
    }));
  } catch (error) {
    console.error('Failed to load runs:', error);
  } finally {
    isLoading.value = false;
  }
};

const loadSettings = async () => {
  try {
    const response = await axios.get('/api/cicd/settings');
    globalSettings.value = { ...globalSettings.value, ...response.data };
  } catch (error) {
    console.error('Failed to load settings:', error);
  }
};

const refreshRuns = async () => {
  await loadRuns();
};

const editGitHubConfig = () => {
  editingPlatform.value = 'github';
  editingConfig.value = githubConfig.value;
  showConfigModal.value = true;
};

const editJenkinsConfig = () => {
  editingPlatform.value = 'jenkins';
  editingConfig.value = jenkinsConfig.value;
  showConfigModal.value = true;
};

const handleConfigSaved = async () => {
  editingPlatform.value = null;
  editingConfig.value = null;
  await loadConfigs();
  await loadRuns();
};

const viewRunDetails = async (id: string) => {
  try {
    const endpoint = activeTab.value === 'github' 
      ? `/api/cicd/github/runs/${id}`
      : `/api/cicd/jenkins/builds/${id}`;
    const response = await axios.get(endpoint);
    selectedRun.value = {
      ...response.data,
      startedAt: new Date(response.data.startedAt),
    };
    showRunModal.value = true;
  } catch (error) {
    console.error('Failed to load run details:', error);
  }
};

const saveSettings = async () => {
  isSaving.value = true;
  try {
    await axios.post('/api/cicd/settings', globalSettings.value);
    alert('Settings saved successfully');
  } catch (error) {
    console.error('Failed to save settings:', error);
    alert('Failed to save settings. Please try again.');
  } finally {
    isSaving.value = false;
  }
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return d.toLocaleDateString();
};

onMounted(async () => {
  await Promise.all([loadConfigs(), loadRuns(), loadSettings()]);
});
</script>

<style scoped>
.cicd-integration-page {
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

.header-actions {
  display: flex;
  gap: 12px;
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

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.tab-button {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.9rem;
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
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.config-section,
.runs-section,
.settings-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.section-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.config-display {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.config-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.config-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
}

.config-value {
  font-size: 0.875rem;
  color: #ffffff;
  font-weight: 500;
}

.config-value.enabled {
  color: #22c55e;
}

.config-value.disabled {
  color: #fc8181;
}

.empty-config {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.runs-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.run-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  cursor: pointer;
  transition: all 0.3s;
}

.run-card:hover {
  transform: translateY(-2px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.run-header {
  margin-bottom: 16px;
}

.run-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.run-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.run-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-success {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failure {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-pending {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.run-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.run-summary {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.summary-item {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.summary-icon {
  width: 16px;
  height: 16px;
}

.summary-icon.passed {
  color: #22c55e;
}

.summary-icon.failed {
  color: #fc8181;
}

.summary-icon.warning {
  color: #fbbf24;
}

.empty-state {
  text-align: center;
  padding: 80px 40px;
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

.settings-group {
  margin-bottom: 32px;
  padding-bottom: 32px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.settings-group:last-child {
  border-bottom: none;
}

.settings-group h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-input {
  width: 100%;
  max-width: 400px;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-help {
  font-size: 0.75rem;
  color: #718096;
  margin-top: 4px;
}

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #ffffff;
  font-size: 0.9rem;
  margin-bottom: 12px;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.settings-actions {
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}
</style>

