<template>
  <div class="application-detail-page">
    <div v-if="loading" class="loading">Loading application details...</div>
    <div v-if="error" class="error">{{ error }}</div>
    
    <div v-if="!loading && !error && application" class="detail-content">
      <!-- Header -->
      <div class="detail-header">
        <Breadcrumb :items="breadcrumbItems" />
        <div class="header-content">
          <div class="header-left">
            <h1 class="page-title">{{ application.name }}</h1>
            <div class="page-meta">
              <span class="status-badge" :class="getStatusClass(application)">
                Status: {{ getStatus(application) }}
              </span>
              <span v-if="application.owner" class="meta-item">Owner: {{ application.owner }}</span>
              <span v-if="application.team" class="meta-item">Team: {{ application.team }}</span>
              <span v-if="lastRun" class="meta-item">Last Run: {{ formatTime(lastRun) }}</span>
            </div>
          </div>
          <div class="header-actions">
            <button @click="runBattery" class="btn-primary">
              <PlayCircle class="btn-icon" />
              Run Test Battery
            </button>
            <button @click="refreshData" class="action-btn" :disabled="isRefreshing">
              <RefreshCw class="action-icon" :class="{ spinning: isRefreshing }" />
              Refresh
            </button>
          </div>
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs-container">
        <div class="tabs">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            :class="['tab-button', { active: activeTab === tab.id }]"
          >
            <component :is="tab.icon" class="tab-icon" />
            {{ tab.label }}
          </button>
        </div>
      </div>

      <!-- Tab Content -->
      <div class="tab-content">
        <!-- Overview Tab -->
        <div v-if="activeTab === 'overview'" class="tab-panel">
          <div class="metrics-grid">
            <div class="metric-card">
              <div class="metric-label">Compliance Score</div>
              <div class="metric-value" :class="getScoreClass(complianceScore)">
                {{ complianceScore }}%
              </div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Total Runs</div>
              <div class="metric-value">{{ totalRuns }}</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Assigned Batteries</div>
              <div class="metric-value">{{ assignedBatteries.length }}</div>
            </div>
            <div class="metric-card">
              <div class="metric-label">Open Issues</div>
              <div class="metric-value failed">{{ openIssuesCount }}</div>
            </div>
          </div>

          <div class="section">
            <h2 class="section-title">Recent Battery Runs</h2>
            <div v-if="recentRuns.length === 0" class="empty-state">
              <p>No recent battery runs</p>
            </div>
            <div v-else class="runs-list">
              <div
                v-for="run in recentRuns"
                :key="run.id"
                class="run-card"
                @click="viewRunDetails(run.id)"
              >
                <div class="run-header">
                  <span class="run-battery">{{ run.batteryName }}</span>
                  <span class="run-status" :class="`status-${run.status}`">
                    {{ run.status }}
                  </span>
                </div>
                <div class="run-meta">
                  <span>{{ formatTime(run.timestamp) }}</span>
                  <span class="run-score" :class="getScoreClass(run.score)">
                    {{ run.score }}% compliance
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div class="section">
            <h2 class="section-title">Top Failing Domains</h2>
            <div v-if="topFailingDomains.length === 0" class="empty-state">
              <p>No failing domains</p>
            </div>
            <div v-else class="domains-list">
              <div
                v-for="domain in topFailingDomains"
                :key="domain.name"
                class="domain-card"
              >
                <div class="domain-header">
                  <span class="domain-name">{{ domain.name }}</span>
                  <span class="domain-score" :class="getScoreClass(domain.score)">
                    {{ domain.score }}%
                  </span>
                </div>
                <div class="domain-issues">
                  {{ domain.issueCount }} issues
                </div>
              </div>
            </div>
          </div>

          <div class="section">
            <h2 class="section-title">Quick Actions</h2>
            <div class="quick-actions">
              <button @click="runBattery" class="quick-action-btn">
                <PlayCircle class="action-icon" />
                Run Test Battery
              </button>
              <button @click="scheduleRuns" class="quick-action-btn">
                <Calendar class="action-icon" />
                Schedule Regular Runs
              </button>
              <button @click="activeTab = 'batteries'" class="quick-action-btn">
                <Battery class="action-icon" />
                Manage Batteries
              </button>
            </div>
          </div>
        </div>

        <!-- Test Batteries Tab -->
        <div v-if="activeTab === 'batteries'" class="tab-panel">
          <div class="section-header">
            <h2 class="section-title">Assigned Test Batteries</h2>
            <div class="section-actions">
              <button @click="showAttachBattery = true" class="btn-primary">
                <Plus class="btn-icon" />
                Attach Battery
              </button>
              <button @click="createAppSpecificBattery" class="btn-secondary">
                <Battery class="btn-icon" />
                Create App-Specific Battery
              </button>
            </div>
          </div>
          <div v-if="assignedBatteries.length === 0" class="empty-state">
            <p>No test batteries assigned to this application</p>
          </div>
          <div v-else class="batteries-list">
            <div
              v-for="battery in assignedBatteries"
              :key="battery.id"
              class="battery-card"
            >
              <div class="battery-header">
                <h3 class="battery-name">{{ battery.name }}</h3>
                <span class="battery-status" :class="getBatteryStatusClass(battery)">
                  {{ getBatteryStatus(battery) }}
                </span>
              </div>
              <div class="battery-info">
                <div class="info-item">
                  <span class="info-label">Next Scheduled Run:</span>
                  <span class="info-value">{{ battery.nextScheduledRun || 'Not scheduled' }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Last Result:</span>
                  <span class="info-value" :class="getStatusClass(battery.lastResult)">
                    {{ battery.lastResult || 'Never run' }}
                  </span>
                </div>
                <div class="info-item">
                  <span class="info-label">Harnesses:</span>
                  <span class="info-value">{{ battery.harnessCount || 0 }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Runs Tab -->
        <div v-if="activeTab === 'runs'" class="tab-panel">
          <h2 class="section-title">Test Battery Runs</h2>
          <div v-if="allRuns.length === 0" class="empty-state">
            <p>No runs found for this application</p>
          </div>
          <div v-else class="runs-table-container">
            <table class="runs-table">
              <thead>
                <tr>
                  <th>Battery</th>
                  <th>Harnesses</th>
                  <th>Environment</th>
                  <th>Result</th>
                  <th>Score</th>
                  <th>Run Time</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="run in allRuns"
                  :key="run.id"
                  class="run-row"
                >
                  <td>{{ run.batteryName }}</td>
                  <td>
                    <div class="harnesses-list">
                      <span
                        v-for="harness in run.harnesses"
                        :key="harness.id"
                        class="harness-tag"
                      >
                        {{ harness.name }}
                      </span>
                    </div>
                  </td>
                  <td>{{ run.environment || 'N/A' }}</td>
                  <td>
                    <span class="status-badge" :class="`status-${run.status}`">
                      {{ run.status }}
                    </span>
                  </td>
                  <td>
                    <span class="score" :class="getScoreClass(run.score)">
                      {{ run.score }}%
                    </span>
                  </td>
                  <td>{{ formatTime(run.timestamp) }}</td>
                  <td>
                    <button @click="viewRunDetails(run.id)" class="btn-link">
                      View Details
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <!-- Issues Tab -->
        <div v-if="activeTab === 'issues'" class="tab-panel">
          <h2 class="section-title">Issues</h2>
          <div v-if="groupedIssues.length === 0" class="empty-state">
            <p>No issues found</p>
          </div>
          <div v-else class="issues-container">
            <div
              v-for="group in groupedIssues"
              :key="group.domain"
              class="domain-group"
            >
              <h3 class="domain-title">{{ getDomainDisplayName(group.domain) }}</h3>
              <div class="issues-list">
                <div
                  v-for="issue in group.issues"
                  :key="issue.id"
                  class="issue-card"
                  :class="`priority-${issue.priority}`"
                >
                  <div class="issue-header">
                    <span class="priority-badge" :class="`priority-${issue.priority}`">
                      {{ issue.priority }}
                    </span>
                    <h4 class="issue-title">{{ issue.title }}</h4>
                  </div>
                  <p class="issue-description">{{ issue.description }}</p>
                  <div class="issue-actions">
                    <button @click="createTicket(issue)" class="btn-link">
                      Create Ticket
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Config & Mappings Tab -->
        <div v-if="activeTab === 'config'" class="tab-panel">
          <h2 class="section-title">Configuration & Mappings</h2>
          <div class="config-sections">
            <div class="config-section">
              <h3 class="config-section-title">Service Endpoints</h3>
              <div v-if="application.endpoints && application.endpoints.length > 0" class="endpoints-list">
                <div
                  v-for="endpoint in application.endpoints"
                  :key="endpoint.id"
                  class="endpoint-item"
                >
                  <span class="endpoint-url">{{ endpoint.url }}</span>
                  <span class="endpoint-method">{{ endpoint.method }}</span>
                </div>
              </div>
              <div v-else class="empty-state">No endpoints configured</div>
            </div>

            <div class="config-section">
              <h3 class="config-section-title">Environments</h3>
              <div v-if="application.environments && application.environments.length > 0" class="environments-list">
                <span
                  v-for="env in application.environments"
                  :key="env"
                  class="env-tag"
                >
                  {{ env }}
                </span>
              </div>
              <div v-else class="empty-state">No environments configured</div>
            </div>

            <div class="config-section">
              <h3 class="config-section-title">Data Stores</h3>
              <div v-if="application.dataStores && application.dataStores.length > 0" class="data-stores-list">
                <div
                  v-for="store in application.dataStores"
                  :key="store.id"
                  class="store-item"
                >
                  <span class="store-name">{{ store.name }}</span>
                  <span class="store-type">{{ store.type }}</span>
                </div>
              </div>
              <div v-else class="empty-state">No data stores configured</div>
            </div>

            <div class="config-section">
              <h3 class="config-section-title">Contract Definitions</h3>
              <div v-if="application.contracts && application.contracts.length > 0" class="contracts-list">
                <div
                  v-for="contract in application.contracts"
                  :key="contract.id"
                  class="contract-item"
                >
                  <span class="contract-name">{{ contract.name }}</span>
                  <span class="contract-version">{{ contract.version }}</span>
                </div>
              </div>
              <div v-else class="empty-state">No contracts defined</div>
            </div>

            <div class="config-section">
              <h3 class="config-section-title">App-Specific Rules</h3>
              <div v-if="application.rules && application.rules.length > 0" class="rules-list">
                <div
                  v-for="rule in application.rules"
                  :key="rule.id"
                  class="rule-item"
                >
                  <span class="rule-name">{{ rule.name }}</span>
                  <span class="rule-status" :class="rule.enabled ? 'enabled' : 'disabled'">
                    {{ rule.enabled ? 'Enabled' : 'Disabled' }}
                  </span>
                </div>
              </div>
              <div v-else class="empty-state">No app-specific rules</div>
            </div>

            <!-- Infrastructure Management -->
            <div class="config-section">
              <div class="config-section-header">
                <h3 class="config-section-title">Infrastructure</h3>
                <button @click="editInfrastructure" class="btn-secondary">
                  <Edit class="btn-icon" />
                  Edit Infrastructure
                </button>
              </div>
              <div v-if="application.infrastructure" class="infrastructure-content">
                <!-- Databases -->
                <div v-if="application.infrastructure.databases && application.infrastructure.databases.length > 0" class="infrastructure-subsection">
                  <h4 class="subsection-title">Databases</h4>
                  <div class="infrastructure-list">
                    <div
                      v-for="db in application.infrastructure.databases"
                      :key="db.id"
                      class="infrastructure-item"
                    >
                      <div class="item-header">
                        <span class="item-name">{{ db.name }}</span>
                        <span class="item-type">{{ db.type }}</span>
                      </div>
                      <div class="item-details">
                        <span>{{ db.host }}:{{ db.port }}/{{ db.database }}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Network Segments -->
                <div v-if="application.infrastructure.networkSegments && application.infrastructure.networkSegments.length > 0" class="infrastructure-subsection">
                  <h4 class="subsection-title">Network Segments</h4>
                  <div class="infrastructure-list">
                    <div
                      v-for="segment in application.infrastructure.networkSegments"
                      :key="segment.id"
                      class="infrastructure-item"
                    >
                      <div class="item-header">
                        <span class="item-name">{{ segment.name }}</span>
                        <span v-if="segment.cidr" class="item-type">{{ segment.cidr }}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- DLP -->
                <div v-if="application.infrastructure.dlp" class="infrastructure-subsection">
                  <h4 class="subsection-title">Data Loss Prevention (DLP)</h4>
                  <div class="infrastructure-item">
                    <div class="item-details">
                      <span v-if="application.infrastructure.dlp.patterns">
                        {{ application.infrastructure.dlp.patterns.length }} pattern(s) configured
                      </span>
                    </div>
                  </div>
                </div>

                <!-- API Gateway -->
                <div v-if="application.infrastructure.apiGateway" class="infrastructure-subsection">
                  <h4 class="subsection-title">API Gateway</h4>
                  <div class="infrastructure-item">
                    <div class="item-details">
                      <span v-if="application.infrastructure.apiGateway.rateLimitConfig">
                        Rate limiting configured
                      </span>
                    </div>
                  </div>
                </div>

                <!-- Other infrastructure types can be added here -->
              </div>
              <div v-else class="empty-state">
                <p>No infrastructure configured</p>
                <button @click="editInfrastructure" class="btn-primary">
                  Add Infrastructure
                </button>
              </div>

            </div>

            <!-- Validator Management -->
            <div class="config-section">
              <div class="config-section-header">
                <h3 class="config-section-title">Validator Management</h3>
                <BulkTogglePanel
                  v-if="validators.length > 0"
                  :items="validators.map(v => ({ id: v.validatorId, name: v.name, enabled: v.enabled }))"
                  @bulk-toggle="handleBulkToggleValidators"
                />
              </div>
              <div v-if="loadingValidators" class="loading-state">Loading validators...</div>
              <div v-else-if="validators.length === 0" class="empty-state">
                No validators available
              </div>
              <div v-else class="validators-list">
                <ValidatorToggle
                  v-for="validator in validators"
                  :key="validator.validatorId"
                  :application-id="applicationId"
                  :validator="validator"
                  @updated="loadValidators"
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Attach Battery Modal -->
    <AttachBatteryModal
      :is-open="showAttachBattery"
      :application-id="applicationId"
      :assigned-battery-ids="assignedBatteries.map(b => b.id)"
      @close="showAttachBattery = false"
      @attached="handleBatteryAttached"
    />

    <!-- Run Details Modal -->
    <RunDetailsModal
      :is-open="showRunDetails"
      :run-id="selectedRunId"
      @close="showRunDetails = false"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import axios from 'axios';
import {
  RefreshCw,
  PlayCircle,
  Battery,
  Calendar,
  Plus,
  LayoutDashboard,
  AlertCircle,
  Settings,
  FileText
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import AttachBatteryModal from '../components/AttachBatteryModal.vue';
import RunDetailsModal from '../components/RunDetailsModal.vue';
import ValidatorToggle from '../components/ValidatorToggle.vue';
import BulkTogglePanel from '../components/BulkTogglePanel.vue';

const route = useRoute();
const router = useRouter();

const applicationId = computed(() => route.params.id as string);
const activeTab = ref<string>((route.query.tab as string) || 'overview');

const loading = ref(true);
const error = ref<string | null>(null);
const isRefreshing = ref(false);
const application = ref<any>(null);
const complianceScore = ref(0);
const totalRuns = ref(0);
const openIssuesCount = ref(0);
const recentRuns = ref<any[]>([]);
const allRuns = ref<any[]>([]);
const assignedBatteries = ref<any[]>([]);
const topFailingDomains = ref<any[]>([]);
const groupedIssues = ref<any[]>([]);
const lastRun = ref<Date | null>(null);
const showAttachBattery = ref(false);
const showRunDetails = ref(false);
const selectedRunId = ref<string | null>(null);
const validators = ref<any[]>([]);
const loadingValidators = ref(false);

const tabs = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'batteries', label: 'Test Batteries', icon: Battery },
  { id: 'runs', label: 'Runs', icon: PlayCircle },
  { id: 'issues', label: 'Issues', icon: AlertCircle },
  { id: 'config', label: 'Config & Mappings', icon: Settings },
];

const breadcrumbItems = computed(() => [
  { label: 'Home', to: '/' },
  { label: 'Applications', to: '/applications' },
  { label: application.value?.name || 'Application' }
]);

// Watch for tab changes in URL
watch(() => route.query.tab, (newTab) => {
  if (newTab && typeof newTab === 'string') {
    activeTab.value = newTab;
  }
});

// Update URL when tab changes
watch(activeTab, (newTab) => {
  router.replace({ query: { ...route.query, tab: newTab } });
  // Load config data when switching to config tab
  if (newTab === 'config') {
    loadInfrastructure();
    loadValidators();
  }
});

const loadApplication = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get(`/api/v1/applications/${applicationId.value}`);
    application.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load application';
    console.error('Error loading application:', err);
  } finally {
    loading.value = false;
  }
};

const loadComplianceScore = async () => {
  try {
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/compliance-score`);
    complianceScore.value = response.data.score || 0;
  } catch (err: any) {
    console.error('Error loading compliance score:', err);
  }
};

const loadRuns = async () => {
  try {
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/runs`);
    const runs = response.data || [];
    allRuns.value = runs.map((run: any) => ({
      ...run,
      timestamp: new Date(run.timestamp || run.createdAt)
    }));
    recentRuns.value = runs.slice(0, 5).map((run: any) => ({
      ...run,
      timestamp: new Date(run.timestamp || run.createdAt)
    }));
    totalRuns.value = runs.length;
    if (runs.length > 0) {
      lastRun.value = new Date(runs[0].timestamp || runs[0].createdAt);
    }
  } catch (err: any) {
    console.error('Error loading runs:', err);
  }
};

const loadBatteries = async () => {
  try {
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/test-batteries`);
    const batteries = response.data || [];
    // Fetch schedule info for each battery
    assignedBatteries.value = await Promise.all(
      batteries.map(async (battery: any) => {
        try {
          // Get battery details to check execution config
          const batteryDetail = await axios.get(`/api/v1/test-batteries/${battery.id}`);
          const execConfig = batteryDetail.data.executionConfig;
          return {
            ...battery,
            nextScheduledRun: execConfig?.schedule?.nextRun 
              ? new Date(execConfig.schedule.nextRun).toLocaleString()
              : execConfig?.schedule?.frequency 
                ? `Scheduled ${execConfig.schedule.frequency}`
                : 'Not scheduled',
            harnessCount: battery.harnessIds?.length || 0,
          };
        } catch (err) {
          return {
            ...battery,
            nextScheduledRun: 'Not scheduled',
            harnessCount: battery.harnessIds?.length || 0,
          };
        }
      })
    );
  } catch (err: any) {
    console.error('Error loading batteries:', err);
  }
};

// Get relevant domains for this application type
const relevantDomains = computed(() => {
  if (!application.value) return [];
  
  const appType = application.value.type;
  const domainMap: Record<string, string[]> = {
    'salesforce_org': ['salesforce'],
    'elastic_cluster': ['elastic'],
    'kubernetes_cluster': ['idp_platform'],
    'api': ['api_security'],
    'web': ['api_security', 'platform_config'],
    'microservice': ['api_security', 'platform_config'],
    'pipeline': ['data_contracts'],
    'database': ['data_contracts', 'identity'],
  };
  
  return domainMap[appType] || [];
});

// Get domain display name
const getDomainDisplayName = (domain: string): string => {
  const domainLabels: Record<string, string> = {
    'api_security': 'API Security',
    'platform_config': 'Platform Configuration',
    'identity': 'Identity',
    'data_contracts': 'Data Contracts',
    'salesforce': 'Salesforce',
    'elastic': 'Elastic',
    'idp_platform': 'IDP / Kubernetes',
  };
  return domainLabels[domain] || domain;
};

const loadIssues = async () => {
  try {
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/issues`);
    const issues = response.data || [];
    openIssuesCount.value = issues.length;
    
    // Group by domain
    const grouped: Record<string, any[]> = {};
    issues.forEach((issue: any) => {
      const domain = issue.domain || 'Other';
      if (!grouped[domain]) {
        grouped[domain] = [];
      }
      grouped[domain].push(issue);
    });
    
    // Filter by relevant domains if application type is specific
    let filteredGrouped = grouped;
    if (relevantDomains.value.length > 0) {
      filteredGrouped = Object.fromEntries(
        Object.entries(grouped).filter(([domain]) => 
          relevantDomains.value.includes(domain) || domain === 'Other'
        )
      );
    }
    
    groupedIssues.value = Object.entries(filteredGrouped).map(([domain, domainIssues]) => ({
      domain,
      issues: domainIssues
    }));
  } catch (err: any) {
    console.error('Error loading issues:', err);
  }
};

const loadTopFailingDomains = async () => {
  try {
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/issues`);
    const issues = response.data || [];
    
    // Filter issues by relevant domains if application type is specific
    let filteredIssues = issues;
    if (relevantDomains.value.length > 0) {
      filteredIssues = issues.filter((issue: any) => {
        const issueDomain = issue.domain || 'Other';
        return relevantDomains.value.includes(issueDomain) || issueDomain === 'Other';
      });
    }
    
    // Group by domain and calculate scores
    const domainStats: Record<string, { count: number; critical: number }> = {};
    filteredIssues.forEach((issue: any) => {
      const domain = issue.domain || 'Other';
      if (!domainStats[domain]) {
        domainStats[domain] = { count: 0, critical: 0 };
      }
      domainStats[domain].count++;
      if (issue.priority === 'critical' || issue.priority === 'high') {
        domainStats[domain].critical++;
      }
    });
    
    topFailingDomains.value = Object.entries(domainStats)
      .map(([name, stats]) => ({
        name: getDomainDisplayName(name),
        domain: name,
        issueCount: stats.count,
        score: Math.max(0, 100 - (stats.critical * 20) - (stats.count * 5))
      }))
      .sort((a, b) => a.score - b.score)
      .slice(0, 4);
  } catch (err: any) {
    console.error('Error loading failing domains:', err);
  }
};

const loadInfrastructure = async () => {
  try {
    // Infrastructure is part of application, already loaded
    // But we can refresh it if needed
    if (application.value) {
      const response = await axios.get(`/api/v1/applications/${applicationId.value}/infrastructure`);
      if (application.value) {
        application.value.infrastructure = response.data;
      }
    }
  } catch (err: any) {
    console.error('Error loading infrastructure:', err);
  }
};

const editInfrastructure = () => {
  // TODO: Open infrastructure edit modal
  alert('Infrastructure editing will be available soon. For now, use PATCH /api/v1/applications/:id with infrastructure field.');
};


const loadValidators = async () => {
  try {
    loadingValidators.value = true;
    const response = await axios.get(`/api/v1/applications/${applicationId.value}/validators/status`);
    validators.value = response.data || [];
  } catch (err: any) {
    console.error('Error loading validators:', err);
    validators.value = [];
  } finally {
    loadingValidators.value = false;
  }
};


const handleBulkToggleValidators = async (items: Array<{ id: string; enabled: boolean; reason?: string }>) => {
  try {
    await axios.patch(`/api/v1/applications/${applicationId.value}/validators/bulk-toggle`, {
      items
    });
    await loadValidators();
  } catch (err: any) {
    console.error('Error bulk toggling validators:', err);
    alert(err.response?.data?.message || 'Failed to update validators');
  }
};

const refreshData = async () => {
  isRefreshing.value = true;
  await Promise.all([
    loadApplication(),
    loadComplianceScore(),
    loadRuns(),
    loadBatteries(),
    loadIssues(),
    loadTopFailingDomains()
  ]);
  setTimeout(() => {
    isRefreshing.value = false;
  }, 500);
};

const runBattery = () => {
  // Navigate to runs page or show run modal
  router.push(`/runs?applicationId=${applicationId.value}`);
};

const scheduleRuns = () => {
  // Show schedule modal or navigate to scheduling page
  alert('Schedule runs functionality to be implemented');
};

const viewRunDetails = (runId: string) => {
  selectedRunId.value = runId;
  showRunDetails.value = true;
};

const handleBatteryAttached = async (batteryId: string) => {
  // Reload batteries to show the newly attached one
  await loadBatteries();
  showAttachBattery.value = false;
};

const createAppSpecificBattery = () => {
  // Navigate to battery creation page with application context
  router.push({
    path: '/tests/batteries/create',
    query: { applicationId: applicationId.value, applicationName: application.value?.name }
  });
};

const createTicket = (issue: any) => {
  // Create ticket integration
  alert(`Create ticket for issue: ${issue.title}`);
};

const getStatus = (app: any): string => {
  const score = complianceScore.value || 0;
  if (score >= 90) return 'At Risk';
  if (score >= 70) return 'Degraded';
  return 'At Risk';
};

const getStatusClass = (app: any): string => {
  const status = getStatus(app);
  if (status === 'At Risk') return 'status-pass';
  if (status === 'Degraded') return 'status-degraded';
  return 'status-fail';
};

const getBatteryStatus = (battery: any): string => {
  if (!battery.lastResult) return 'Never Run';
  if (battery.lastResult === 'passed') return 'Passing';
  if (battery.lastResult === 'failed') return 'Failing';
  return battery.lastResult;
};

const getBatteryStatusClass = (battery: any): string => {
  const status = getBatteryStatus(battery);
  if (status === 'Passing') return 'status-pass';
  if (status === 'Failing') return 'status-fail';
  return 'status-never';
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatTime = (date: Date | string | null): string => {
  if (!date) return 'Never';
  const d = typeof date === 'string' ? new Date(date) : date;
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return d.toLocaleDateString();
};

onMounted(async () => {
  await refreshData();
});
</script>

<style scoped>
.application-detail-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.detail-content {
  width: 100%;
}

.detail-header {
  margin-bottom: 32px;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 24px;
  margin-top: 16px;
}

.header-left {
  flex: 1;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 12px 0;
}

.page-meta {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}

.meta-item {
  font-size: 0.875rem;
  color: #a0aec0;
}

.status-badge {
  padding: 6px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-pass {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-degraded {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-fail {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-never {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.header-actions {
  display: flex;
  gap: 12px;
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

.action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.action-btn:hover:not(:disabled) {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.action-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-icon,
.action-icon {
  width: 18px;
  height: 18px;
}

.action-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.tabs-container {
  margin-bottom: 32px;
}

.tabs {
  display: flex;
  gap: 8px;
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
  font-size: 0.95rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
  bottom: -1px;
}

.tab-button:hover {
  color: #ffffff;
  background: rgba(79, 172, 254, 0.05);
}

.tab-button.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
  background: rgba(79, 172, 254, 0.05);
}

.tab-icon {
  width: 18px;
  height: 18px;
}

.tab-content {
  min-height: 400px;
}

.tab-panel {
  animation: fadeIn 0.3s;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 24px;
  margin-bottom: 32px;
}

.metric-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.metric-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
}

.metric-value.score-high {
  color: #22c55e;
}

.metric-value.score-medium {
  color: #fbbf24;
}

.metric-value.score-low,
.metric-value.failed {
  color: #fc8181;
}

.section {
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

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 24px 0;
}

.section-actions {
  display: flex;
  gap: 12px;
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.runs-list,
.domains-list,
.batteries-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.run-card,
.domain-card,
.battery-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
  cursor: pointer;
  transition: all 0.2s;
}

.run-card:hover,
.battery-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  background: rgba(15, 20, 25, 0.8);
}

.run-header,
.battery-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.run-battery,
.battery-name {
  font-weight: 600;
  color: #ffffff;
}

.run-status,
.battery-status {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.run-meta,
.battery-info {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.run-score {
  font-weight: 600;
}

.domain-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.domain-name {
  font-weight: 600;
  color: #ffffff;
}

.domain-score {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.domain-issues {
  font-size: 0.875rem;
  color: #a0aec0;
}

.quick-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.quick-action-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 20px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.quick-action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.runs-table-container {
  overflow-x: auto;
}

.runs-table {
  width: 100%;
  border-collapse: collapse;
}

.runs-table th {
  text-align: left;
  padding: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.runs-table td {
  padding: 12px;
  color: #ffffff;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.run-row {
  cursor: pointer;
  transition: background 0.2s;
}

.run-row:hover {
  background: rgba(79, 172, 254, 0.05);
}

.harnesses-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.harness-tag {
  padding: 4px 10px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  font-size: 0.75rem;
  color: #4facfe;
}

.btn-link {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.btn-link:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.issues-container {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.domain-group {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.domain-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.issues-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.issue-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 16px;
}

.issue-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.priority-badge {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.priority-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.priority-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.priority-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.priority-low {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.issue-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.issue-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 8px 0;
}

.issue-actions {
  margin-top: 12px;
}

.config-sections {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.config-section {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.config-section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.config-section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.test-configs-list,
.validators-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.endpoints-list,
.environments-list,
.data-stores-list,
.contracts-list,
.rules-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.endpoint-item,
.store-item,
.contract-item,
.rule-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.endpoint-url,
.store-name,
.contract-name,
.rule-name {
  font-weight: 500;
  color: #ffffff;
}

.endpoint-method,
.store-type,
.contract-version,
.rule-status {
  font-size: 0.875rem;
  color: #a0aec0;
}

.rule-status.enabled {
  color: #22c55e;
}

.rule-status.disabled {
  color: #a0aec0;
}

.environments-list {
  flex-direction: row;
  flex-wrap: wrap;
}

.infrastructure-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.infrastructure-subsection {
  margin-bottom: 16px;
}

.subsection-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 12px 0;
}

.infrastructure-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.infrastructure-item {
  padding: 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.item-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.item-name {
  font-weight: 500;
  color: #ffffff;
}

.item-type {
  font-size: 0.875rem;
  color: #a0aec0;
}

.item-details {
  font-size: 0.875rem;
  color: #a0aec0;
}

.deprecated-section {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.deprecation-notice {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 16px;
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 8px;
  margin-bottom: 16px;
}

.deprecation-icon {
  color: #f59e0b;
  flex-shrink: 0;
  margin-top: 2px;
}

.deprecation-notice div {
  flex: 1;
  color: #fbbf24;
  font-size: 0.875rem;
  line-height: 1.6;
}

.deprecation-notice strong {
  color: #ffffff;
}

.env-tag {
  padding: 6px 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #4facfe;
}

.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.loading {
  text-align: center;
  padding: 50px;
  color: #4facfe;
  font-size: 1.2em;
}

.error {
  text-align: center;
  padding: 20px;
  color: #fc8181;
  font-size: 1.2em;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  margin: 20px 0;
}

.score {
  font-weight: 600;
}
</style>
