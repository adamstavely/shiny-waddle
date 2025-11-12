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

    <!-- Findings List -->
    <div class="findings-list">
      <div
        v-for="finding in filteredFindings"
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
            <span class="detail-value risk-score" :class="getRiskScoreClass(finding.riskScore)">
              {{ finding.riskScore }}
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
import { ref, computed, onMounted } from 'vue';
import {
  ShieldAlert,
  Upload,
  Download,
  Eye,
  CheckCircle2,
  Trash2
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import ImportFindingsModal from '../components/ImportFindingsModal.vue';
import FindingDetailModal from '../components/FindingDetailModal.vue';

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
const selectedFinding = ref<any>(null);

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
    selectedFinding.value = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
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

onMounted(async () => {
  await loadFindings();
});
</script>

<style scoped>
.unified-findings-page {
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

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
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

.statistics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.stat-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
}

.stat-value.critical {
  color: #fc8181;
}

.stat-value.high {
  color: #fbbf24;
}

.filters {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
  flex-wrap: wrap;
}

.search-input,
.filter-dropdown {
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
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
  gap: 16px;
}

.finding-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.finding-card:hover {
  transform: translateY(-2px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.finding-card.severity-critical {
  border-left: 4px solid #fc8181;
}

.finding-card.severity-high {
  border-left: 4px solid #fbbf24;
}

.finding-card.severity-medium {
  border-left: 4px solid #4facfe;
}

.finding-card.severity-low {
  border-left: 4px solid #a0aec0;
}

.finding-header {
  margin-bottom: 16px;
}

.finding-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
  gap: 16px;
}

.finding-title-group {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.finding-icon {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
  margin-top: 2px;
}

.finding-icon.icon-critical {
  color: #fc8181;
}

.finding-icon.icon-high {
  color: #fbbf24;
}

.finding-icon.icon-medium {
  color: #4facfe;
}

.finding-icon.icon-low {
  color: #a0aec0;
}

.finding-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.finding-badges {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.severity-badge,
.source-badge,
.scanner-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.severity-badge.badge-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.severity-badge.badge-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-badge.badge-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.severity-badge.badge-low {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.source-badge {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.scanner-badge {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.finding-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.finding-description {
  font-size: 0.9rem;
  color: #ffffff;
  margin: 0 0 16px 0;
  line-height: 1.6;
}

.finding-details {
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  margin-bottom: 16px;
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
}

.detail-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.detail-value {
  font-size: 0.875rem;
  color: #ffffff;
}

.risk-score {
  font-weight: 600;
}

.risk-score.risk-high {
  color: #fc8181;
}

.risk-score.risk-medium {
  color: #fbbf24;
}

.risk-score.risk-low {
  color: #22c55e;
}

.compliance-badges {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}

.compliance-badge {
  padding: 4px 8px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.75rem;
  color: #4facfe;
}

.finding-actions {
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
}

.action-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.view-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.delete-btn:hover {
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
</style>

