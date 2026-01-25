<template>
  <div class="unified-findings-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Security Findings</h1>
          <p class="page-description">Unified view of security findings from all scanners</p>
        </div>
        <div class="header-actions">
          <button @click="calculateAllRiskScores" class="btn-secondary" :disabled="isCalculatingRisk">
            <ShieldAlert class="btn-icon" />
            {{ isCalculatingRisk ? 'Calculating...' : 'Calculate Risk Scores' }}
          </button>
          <button @click="showPrioritized = !showPrioritized" class="btn-secondary">
            <TrendingUp class="btn-icon" />
            {{ showPrioritized ? 'Show All' : 'Show Prioritized' }}
          </button>
          <button @click="showImportModal = true" class="btn-secondary">
            <Upload class="btn-icon" />
            Import Findings
          </button>
          <button @click="exportToECS" class="btn-secondary">
            <Download class="btn-icon" />
            Export ECS
          </button>
        </div>
      </div>
    </div>

    <!-- Statistics Cards -->
    <div class="statistics-grid">
      <div class="stat-card">
        <div class="stat-label">Total Findings</div>
        <div class="stat-value">{{ statistics.total }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Critical</div>
        <div class="stat-value critical">{{ statistics.bySeverity.critical || 0 }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">High</div>
        <div class="stat-value high">{{ statistics.bySeverity.high || 0 }}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Open</div>
        <div class="stat-value">{{ statistics.byStatus.open || 0 }}</div>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search findings..."
        class="search-input"
      />
      <Dropdown
        v-model="filterSource"
        :options="sourceOptions"
        placeholder="All Sources"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterScanner"
        :options="scannerOptions"
        placeholder="All Scanners"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterSeverity"
        :options="severityOptions"
        placeholder="All Severities"
        class="filter-dropdown"
      />
      <Dropdown
        v-model="filterStatus"
        :options="statusOptions"
        placeholder="All Statuses"
        class="filter-dropdown"
      />
    </div>

    <!-- Risk Aggregation Cards -->
    <div v-if="riskAggregation" class="risk-aggregation-grid">
      <div class="aggregation-card">
        <h3>Organization Risk</h3>
        <div class="aggregation-score" :class="getRiskScoreClass(riskAggregation.organization.riskScore)">
          {{ riskAggregation.organization.riskScore.toFixed(1) }}
        </div>
        <div class="aggregation-details">
          <span>Total: {{ riskAggregation.organization.totalFindings }}</span>
          <span>Critical: {{ riskAggregation.organization.criticalCount }}</span>
        </div>
      </div>
    </div>

    <!-- Findings List -->
    <div class="findings-list">
      <div
        v-for="finding in (showPrioritized ? prioritizedFindings : filteredFindings)"
        :key="finding.id"
        class="finding-card"
        :class="`severity-${finding.severity}`"
        @click="viewFinding(finding.id)"
      >
        <div class="finding-header">
          <div class="finding-title-row">
            <div class="finding-title-group">
              <ShieldAlert class="finding-icon" :class="`icon-${finding.severity}`" />
              <h3 class="finding-title">{{ finding.title }}</h3>
            </div>
            <div class="finding-badges">
              <span class="severity-badge" :class="`badge-${finding.severity}`">
                {{ finding.severity }}
              </span>
              <span class="source-badge">{{ finding.source.toUpperCase() }}</span>
              <span class="scanner-badge">{{ finding.scannerId }}</span>
            </div>
          </div>
          <p class="finding-meta">
            <span v-if="finding.asset.applicationId">{{ finding.asset.applicationId }}</span>
            <span v-if="finding.asset.component"> • {{ finding.asset.component }}</span>
            <span v-if="finding.asset.location?.file?.path"> • {{ finding.asset.location.file.path }}</span>
            <span v-if="finding.asset.location?.url?.original"> • {{ finding.asset.location.url.original }}</span>
            <span> • {{ formatDate(finding.createdAt) }}</span>
          </p>
        </div>

        <p class="finding-description">{{ finding.description }}</p>

        <div class="finding-details">
          <div class="detail-item" v-if="finding.vulnerability?.cve?.id">
            <span class="detail-label">CVE:</span>
            <span class="detail-value">{{ finding.vulnerability.cve.id }}</span>
          </div>
          <div class="detail-item" v-if="finding.vulnerability?.classification">
            <span class="detail-label">CWE:</span>
            <span class="detail-value">{{ finding.vulnerability.classification }}</span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Risk Score:</span>
            <span class="detail-value risk-score" :class="getRiskScoreClass(finding.riskScore || finding.enhancedRiskScore?.adjustedScore || 0)">
              {{ finding.enhancedRiskScore?.adjustedScore?.toFixed(1) || finding.riskScore || 'N/A' }}
            </span>
            <span v-if="finding.enhancedRiskScore?.priority" class="priority-badge" :class="getRiskScoreClass(finding.enhancedRiskScore.priority)">
              Priority: {{ finding.enhancedRiskScore.priority.toFixed(0) }}
            </span>
          </div>
          <div class="detail-item" v-if="finding.compliance?.frameworks">
            <span class="detail-label">Compliance:</span>
            <div class="compliance-badges">
              <span
                v-for="framework in finding.compliance.frameworks"
                :key="framework"
                class="compliance-badge"
              >
                {{ framework }}
              </span>
            </div>
          </div>
        </div>

        <div class="finding-actions">
          <button @click.stop="viewFinding(finding.id)" class="action-btn view-btn">
            <Eye class="action-icon" />
            View Details
          </button>
          <button
            @click.stop="updateFindingStatus(finding.id, finding.status === 'open' ? 'in-progress' : 'open')"
            class="action-btn"
            v-if="finding.status === 'open' || finding.status === 'in-progress'"
          >
            <CheckCircle2 class="action-icon" />
            {{ finding.status === 'open' ? 'Start' : 'Resolve' }}
          </button>
          <button @click.stop="deleteFinding(finding.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredFindings.length === 0 && !isLoading" class="empty-state">
      <ShieldAlert class="empty-icon" />
      <h3>No findings found</h3>
      <p>Import findings from scanners to get started</p>
      <button @click="showImportModal = true" class="btn-primary">
        Import Findings
      </button>
    </div>

    <!-- Import Modal -->
    <ImportFindingsModal
      v-model:isOpen="showImportModal"
      @imported="handleFindingsImported"
    />

    <!-- Finding Detail Modal -->
    <FindingDetailModal
      v-model:isOpen="showDetailModal"
      :finding="selectedFinding"
      @updated="handleFindingUpdated"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue';
import { useRoute } from 'vue-router';
import {
  ShieldAlert,
  Upload,
  Download,
  Eye,
  CheckCircle2,
  Trash2,
  TrendingUp
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ImportFindingsModal from '../components/ImportFindingsModal.vue';
import FindingDetailModal from '../components/FindingDetailModal.vue';

const route = useRoute();

const breadcrumbItems = [
  { label: 'Security Findings', icon: ShieldAlert }
];

const searchQuery = ref('');
const filterSource = ref('');
const filterScanner = ref('');
const filterSeverity = ref('');
const filterStatus = ref('');
const isLoading = ref(false);
const showImportModal = ref(false);
const showDetailModal = ref(false);
const showPrioritized = ref(false);
const isCalculatingRisk = ref(false);
const selectedFinding = ref<any>(null);
const prioritizedFindings = ref<any[]>([]);
const riskAggregation = ref<any>(null);

const findings = ref<any[]>([]);
const statistics = ref({
  total: 0,
  bySource: {} as Record<string, number>,
  bySeverity: {} as Record<string, number>,
  byStatus: {} as Record<string, number>,
  byScanner: {} as Record<string, number>,
});

const sourceOptions = computed(() => {
  const sources = new Set(findings.value.map(f => f.source));
  return [
    { label: 'All Sources', value: '' },
    ...Array.from(sources).map(s => ({ label: s.toUpperCase(), value: s })),
  ];
});

const scannerOptions = computed(() => {
  const scanners = new Set(findings.value.map(f => f.scannerId));
  return [
    { label: 'All Scanners', value: '' },
    ...Array.from(scanners).map(s => ({ label: s, value: s })),
  ];
});

const severityOptions = [
  { label: 'All Severities', value: '' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
  { label: 'Info', value: 'info' },
];

const statusOptions = [
  { label: 'All Statuses', value: '' },
  { label: 'Open', value: 'open' },
  { label: 'In Progress', value: 'in-progress' },
  { label: 'Resolved', value: 'resolved' },
  { label: 'False Positive', value: 'false-positive' },
  { label: 'Risk Accepted', value: 'risk-accepted' },
];

const filteredFindings = computed(() => {
  return findings.value.filter(finding => {
    const matchesSearch = finding.title?.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      finding.description?.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesSource = !filterSource.value || finding.source === filterSource.value;
    const matchesScanner = !filterScanner.value || finding.scannerId === filterScanner.value;
    const matchesSeverity = !filterSeverity.value || finding.severity === filterSeverity.value;
    const matchesStatus = !filterStatus.value || finding.status === filterStatus.value;
    return matchesSearch && matchesSource && matchesScanner && matchesSeverity && matchesStatus;
  });
});

const loadFindings = async () => {
  isLoading.value = true;
  try {
    const [findingsRes, statsRes] = await Promise.all([
      axios.get('/api/unified-findings'),
      axios.get('/api/unified-findings/statistics'),
    ]);
    findings.value = findingsRes.data.map((f: any) => ({
      ...f,
      createdAt: new Date(f.createdAt),
      updatedAt: new Date(f.updatedAt),
    }));
    statistics.value = statsRes.data;
  } catch (error) {
    console.error('Failed to load findings:', error);
  } finally {
    isLoading.value = false;
  }
};

const viewFinding = async (id: string) => {
  try {
    const response = await axios.get(`/api/unified-findings/${id}`);
    let finding = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
    
    // Calculate risk score if not present
    if (!finding.enhancedRiskScore) {
      try {
        const riskScoreRes = await axios.post(`/api/unified-findings/${id}/risk-score`);
        finding.enhancedRiskScore = {
          ...riskScoreRes.data,
          calculatedAt: new Date(riskScoreRes.data.calculatedAt),
        };
      } catch (error) {
        console.error('Failed to calculate risk score:', error);
      }
    }
    
    selectedFinding.value = finding;
    showDetailModal.value = true;
  } catch (error) {
    console.error('Failed to load finding:', error);
  }
};

const updateFindingStatus = async (id: string, status: string) => {
  try {
    await axios.patch(`/api/unified-findings/${id}`, { status });
    await loadFindings();
  } catch (error) {
    console.error('Failed to update finding:', error);
    alert('Failed to update finding. Please try again.');
  }
};

const deleteFinding = async (id: string) => {
  if (!confirm('Are you sure you want to delete this finding?')) return;
  try {
    await axios.delete(`/api/unified-findings/${id}`);
    await loadFindings();
  } catch (error) {
    console.error('Failed to delete finding:', error);
    alert('Failed to delete finding. Please try again.');
  }
};

const exportToECS = async () => {
  try {
    const response = await axios.get('/api/unified-findings/ecs', {
      params: {
        source: filterSource.value || undefined,
        scannerId: filterScanner.value || undefined,
        severity: filterSeverity.value || undefined,
        status: filterStatus.value || undefined,
      },
    });
    
    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `findings-ecs-${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Failed to export findings:', error);
    alert('Failed to export findings. Please try again.');
  }
};

const handleFindingsImported = async () => {
  await loadFindings();
};

const handleFindingUpdated = async () => {
  await loadFindings();
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

const getRiskScoreClass = (score: number): string => {
  if (score >= 75) return 'risk-high';
  if (score >= 50) return 'risk-medium';
  return 'risk-low';
};

const calculateAllRiskScores = async () => {
  isCalculatingRisk.value = true;
  try {
    await axios.post('/api/unified-findings/risk-scores/calculate-all');
    await loadFindings();
    await loadPrioritizedFindings();
    await loadRiskAggregation();
  } catch (error) {
    console.error('Failed to calculate risk scores:', error);
    alert('Failed to calculate risk scores. Please try again.');
  } finally {
    isCalculatingRisk.value = false;
  }
};

const loadPrioritizedFindings = async () => {
  try {
    const response = await axios.get('/api/unified-findings/prioritized', {
      params: { limit: 50 }
    });
    prioritizedFindings.value = response.data.map((item: any) => ({
      ...item.finding,
      enhancedRiskScore: item.riskScore,
      createdAt: new Date(item.finding.createdAt),
      updatedAt: new Date(item.finding.updatedAt),
    }));
  } catch (error) {
    console.error('Failed to load prioritized findings:', error);
  }
};

const loadRiskAggregation = async () => {
  try {
    const [orgRes] = await Promise.all([
      axios.get('/api/unified-findings/risk-aggregation/organization'),
    ]);
    riskAggregation.value = {
      organization: orgRes.data,
    };
  } catch (error) {
    console.error('Failed to load risk aggregation:', error);
  }
};

onMounted(async () => {
  await loadFindings();
  await loadPrioritizedFindings();
  await loadRiskAggregation();
  
  // Check if findingId is in query params (from notification navigation)
  if (route.query.findingId && typeof route.query.findingId === 'string') {
    await viewFinding(route.query.findingId);
  }
});

// Watch for route query changes (e.g., when navigating from notifications)
watch(() => route.query.findingId, async (findingId) => {
  if (findingId && typeof findingId === 'string' && !showDetailModal.value) {
    await viewFinding(findingId);
  }
});
</script>

<style scoped>
.unified-findings-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
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

.header-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.page-title {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.page-description {
  font-size: var(--font-size-lg);
  color: var(--color-text-secondary);
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
  font-size: var(--font-size-sm);
}

.btn-primary {
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  color: var(--color-primary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.statistics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.stat-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  text-align: center;
}

.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-sm);
}

.stat-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.stat-value.critical {
  color: var(--color-error);
}

.stat-value.high {
  color: var(--color-warning);
}

.filters {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-dropdown {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown {
  min-width: 150px;
}

.findings-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.finding-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.finding-card:hover {
  transform: translateY(-2px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.finding-card.severity-critical {
  border-left: 4px solid var(--color-error);
}

.finding-card.severity-high {
  border-left: 4px solid var(--color-warning);
}

.finding-card.severity-medium {
  border-left: 4px solid var(--color-primary);
}

.finding-card.severity-low {
  border-left: 4px solid var(--color-text-secondary);
}

.finding-header {
  margin-bottom: var(--spacing-md);
}

.finding-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
  gap: var(--spacing-md);
}

.finding-title-group {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  flex: 1;
}

.finding-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
  margin-top: 2px;
}

.finding-icon.icon-critical {
  color: var(--color-error);
}

.finding-icon.icon-high {
  color: var(--color-warning);
}

.finding-icon.icon-medium {
  color: var(--color-primary);
}

.finding-icon.icon-low {
  color: var(--color-text-secondary);
}

.finding-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.finding-badges {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.severity-badge,
.source-badge,
.scanner-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.severity-badge.badge-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.severity-badge.badge-high {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.severity-badge.badge-medium {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.severity-badge.badge-low {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
}

.source-badge {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.scanner-badge {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.finding-meta {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.finding-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
  line-height: var(--line-height-normal);
}

.finding-details {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
}

.detail-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.detail-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
  font-weight: var(--font-weight-medium);
}

.detail-value {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.risk-score {
  font-weight: var(--font-weight-semibold);
}

.risk-score.risk-high {
  color: var(--color-error);
}

.risk-score.risk-medium {
  color: var(--color-warning);
}

.risk-score.risk-low {
  color: var(--color-success);
}

.compliance-badges {
  display: flex;
  gap: var(--spacing-xs);
  flex-wrap: wrap;
}

.compliance-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.finding-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.action-btn {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.action-btn:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.view-btn:hover {
  background: var(--color-success-bg);
  border-color: var(--color-success);
  color: var(--color-success);
}

.delete-btn:hover {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  color: var(--color-error);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-lg);
  opacity: 0.5;
}

.empty-state h3 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-lg);
}

.risk-aggregation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.aggregation-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
  text-align: center;
}

.aggregation-card h3 {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-sm) 0;
  font-weight: var(--font-weight-medium);
}

.aggregation-score {
  font-size: var(--font-size-3xl);
  font-weight: 700;
  margin-bottom: 8px;
}

.aggregation-score.risk-high {
  color: var(--color-error);
}

.aggregation-score.risk-medium {
  color: var(--color-warning);
}

.aggregation-score.risk-low {
  color: var(--color-success);
}

.aggregation-details {
  display: flex;
  justify-content: space-around;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-top: var(--spacing-sm);
}

.priority-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  margin-left: var(--spacing-sm);
}

.priority-badge.risk-high {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.priority-badge.risk-medium {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.priority-badge.risk-low {
  background: var(--color-success-bg);
  color: var(--color-success);
}
</style>

