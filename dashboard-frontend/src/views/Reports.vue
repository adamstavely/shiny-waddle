<template>
  <div class="reports-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Reports</h1>
          <p class="page-description">View and download compliance reports</p>
        </div>
        <button @click="openGenerateModal" class="btn-primary">
          <FileText class="btn-icon" />
          Generate Report
        </button>
      </div>
    </div>

    <!-- Filters -->
    <div class="filters">
      <input
        v-model="searchQuery"
        type="text"
        placeholder="Search reports..."
        class="search-input"
      />
      <Dropdown
        v-model="filterFormat"
        :options="formatOptions"
        placeholder="All Formats"
        class="filter-dropdown"
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
        v-model="filterValidator"
        :options="validatorOptions"
        placeholder="All Validators"
        class="filter-dropdown"
      />
      <input
        v-model="filterDateFrom"
        type="date"
        class="filter-date"
        placeholder="From Date"
      />
      <input
        v-model="filterDateTo"
        type="date"
        class="filter-date"
        placeholder="To Date"
      />
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="loading-state">
      <p>Loading reports...</p>
    </div>

    <!-- Reports List -->
    <div v-else class="reports-grid">
      <div
        v-for="report in filteredReports"
        :key="report.id"
        class="report-card"
        @click="viewReport(report.id)"
      >
        <div class="report-header">
          <div class="report-title-row">
            <h3 class="report-name">{{ report.name }}</h3>
            <span class="report-status" :class="`status-${report.status}`">
              {{ report.status }}
            </span>
          </div>
          <p class="report-meta">{{ report.application }} • {{ report.team }}</p>
        </div>

        <div class="report-info">
          <div class="info-item">
            <span class="info-label">Format:</span>
            <span class="info-value format-badge" :class="`format-${report.format}`">
              {{ report.format.toUpperCase() }}
            </span>
          </div>
          <div class="info-item">
            <span class="info-label">Generated:</span>
            <span class="info-value">{{ formatDate(report.generatedAt) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Compliance Score:</span>
            <span class="info-value score" :class="getScoreClass(report.complianceScore)">
              {{ report.complianceScore }}%
            </span>
          </div>
          <div class="info-item">
            <span class="info-label">Tests:</span>
            <span class="info-value">{{ report.testCount }} total</span>
          </div>
          <div class="info-item" v-if="report.validators && report.validators.length > 0">
            <span class="info-label">Validators:</span>
            <div class="validator-badges">
              <span
                v-for="validator in report.validators"
                :key="validator.id"
                class="validator-badge"
              >
                {{ validator.name }}
              </span>
            </div>
          </div>
        </div>

        <div class="report-summary">
          <div class="summary-item">
            <CheckCircle2 class="summary-icon passed" />
            <span>{{ report.passedTests }} passed</span>
          </div>
          <div class="summary-item">
            <X class="summary-icon failed" />
            <span>{{ report.failedTests }} failed</span>
          </div>
        </div>

        <div class="report-actions">
          <button @click.stop="downloadReport(report.id, report.format)" class="action-btn">
            <Download class="action-icon" />
            Download
          </button>
          <button @click.stop="viewReport(report.id)" class="action-btn view-btn">
            <Eye class="action-icon" />
            View
          </button>
          <button @click.stop="deleteReport(report.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="filteredReports.length === 0" class="empty-state">
      <FileText class="empty-icon" />
      <h3>No reports found</h3>
      <p>Generate a report to get started</p>
      <button @click="openGenerateModal" class="btn-primary">
        Generate Report
      </button>
    </div>

    <!-- Generate Report Modal -->
    <GenerateReportModal
      v-model:isOpen="showGenerateModal"
      :applications="applications"
      :teams="teams"
      :validators="validators"
      :test-batteries="testBatteries"
      :test-harnesses="testHarnesses"
      @generated="handleReportGenerated"
    />

    <!-- Report Viewer Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="viewingReport" class="modal-overlay" @click="closeViewer">
          <div class="modal-content report-viewer" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <FileText class="modal-title-icon" />
                <h2>{{ viewingReport?.name }}</h2>
              </div>
              <div class="modal-header-actions">
                <button @click="downloadReport(viewingReport.id, viewingReport.format)" class="action-btn-header">
                  <Download class="action-icon" />
                  Download
                </button>
                <button @click="closeViewer" class="modal-close">
                  <X class="close-icon" />
                </button>
              </div>
            </div>
            <div class="modal-body">
              <!-- Report Summary -->
              <div v-if="viewingReport?.content" class="report-summary-section">
                <div class="summary-cards">
                  <div class="summary-card">
                    <div class="summary-card-label">Compliance Score</div>
                    <div class="summary-card-value" :class="getScoreClass(viewingReport.complianceScore)">
                      {{ viewingReport.complianceScore }}%
                    </div>
                  </div>
                  <div class="summary-card">
                    <div class="summary-card-label">Total Tests</div>
                    <div class="summary-card-value">{{ viewingReport.testCount }}</div>
                  </div>
                  <div class="summary-card">
                    <div class="summary-card-label">Passed</div>
                    <div class="summary-card-value passed">{{ viewingReport.passedTests }}</div>
                  </div>
                  <div class="summary-card">
                    <div class="summary-card-label">Failed</div>
                    <div class="summary-card-value failed">{{ viewingReport.failedTests }}</div>
                  </div>
                </div>

                <!-- Charts Section -->
                <div v-if="viewingReport.content.scores" class="charts-section">
                  <div class="chart-container">
                    <h3>Compliance by Category</h3>
                    <div class="score-bars">
                      <div
                        v-for="(score, category) in viewingReport.content.scores.byCategory"
                        :key="category"
                        class="score-bar-item"
                      >
                        <div class="score-bar-label">{{ formatCategory(category) }}</div>
                        <div class="score-bar">
                          <div
                            class="score-bar-fill"
                            :style="{ width: `${score}%` }"
                            :class="getScoreClass(score)"
                          ></div>
                          <span class="score-bar-value">{{ score }}%</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Detailed Content -->
                <div class="report-content-section">
                  <h3>Report Details</h3>
                  <div v-if="viewingReport.format === 'html'" class="html-report" v-html="viewingReport.content.html || viewingReport.content"></div>
                  <div v-else-if="viewingReport.format === 'json'" class="json-report">
                    <pre>{{ JSON.stringify(viewingReport.content, null, 2) }}</pre>
                  </div>
                  <div v-else class="xml-report">
                    <pre>{{ viewingReport.content }}</pre>
                  </div>
                </div>
              </div>
              <div v-else class="report-loading">
                <p>Loading report content...</p>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  FileText,
  Download,
  Eye,
  Trash2,
  X,
  CheckCircle2
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import GenerateReportModal from '../components/GenerateReportModal.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Reports' }
];

const searchQuery = ref('');
const filterFormat = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterValidator = ref('');
const filterDateFrom = ref('');
const filterDateTo = ref('');
const viewingReport = ref<any>(null);
const validators = ref<any[]>([]);
const testBatteries = ref<any[]>([]);
const testHarnesses = ref<any[]>([]);
const showGenerateModal = ref(false);
const reports = ref<any[]>([]);
const isLoading = ref(false);

const applications = computed(() => {
  return [...new Set(reports.value.map(r => r.application))];
});

const teams = computed(() => {
  return [...new Set(reports.value.map(r => r.team))];
});

const formatOptions = computed(() => [
  { label: 'All Formats', value: '' },
  { label: 'JSON', value: 'json' },
  { label: 'HTML', value: 'html' },
  { label: 'XML', value: 'xml' }
]);

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

const validatorOptions = computed(() => {
  return [
    { label: 'All Validators', value: '' },
    ...validators.value.map(v => ({ label: v.name, value: v.id }))
  ];
});

const filteredReports = computed(() => {
  return reports.value.filter(report => {
    const matchesSearch = report.name.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesFormat = !filterFormat.value || report.format === filterFormat.value;
    const matchesApp = !filterApplication.value || report.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || report.team === filterTeam.value;
    const matchesValidator = !filterValidator.value || 
      (report.validators && report.validators.some((v: any) => v.id === filterValidator.value));
    const matchesDate = (!filterDateFrom.value || new Date(report.generatedAt) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(report.generatedAt) <= new Date(filterDateTo.value));
    return matchesSearch && matchesFormat && matchesApp && matchesTeam && matchesValidator && matchesDate;
  });
});

const openGenerateModal = () => {
  showGenerateModal.value = true;
};

const handleReportGenerated = async (report: any) => {
  // Reload reports to get the new one
  await loadReports();
};

const loadReports = async () => {
  isLoading.value = true;
  try {
    const response = await axios.get('/api/reports');
    reports.value = response.data.map((report: any) => ({
      ...report,
      generatedAt: new Date(report.generatedAt),
    }));
  } catch (error) {
    console.error('Failed to load reports:', error);
  } finally {
    isLoading.value = false;
  }
};

const viewReport = async (id: string) => {
  try {
    const response = await axios.get(`/api/reports/${id}`);
    viewingReport.value = {
      ...response.data,
      generatedAt: new Date(response.data.generatedAt),
    };
  } catch (error) {
    console.error('Failed to load report:', error);
    // Fallback to local data
    const report = reports.value.find(r => r.id === id);
    if (report) {
      viewingReport.value = report;
    }
  }
};

const closeViewer = () => {
  viewingReport.value = null;
};

const downloadReport = async (id: string, format: string) => {
  try {
    const response = await axios.get(`/api/reports/${id}/download`, {
      responseType: 'blob',
    });
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    const report = reports.value.find(r => r.id === id);
    link.setAttribute('download', `${report?.name || 'report'}.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('Failed to download report:', error);
    alert('Failed to download report. Please try again.');
  }
};

const deleteReport = async (id: string) => {
  if (confirm('Are you sure you want to delete this report?')) {
    try {
      await axios.delete(`/api/reports/${id}`);
      await loadReports();
    } catch (error) {
      console.error('Failed to delete report:', error);
      alert('Failed to delete report. Please try again.');
    }
  }
};

const formatDate = (date: Date): string => {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 1) return 'Just now';
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};

const formatCategory = (category: string): string => {
  return category
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (str) => str.toUpperCase())
    .trim();
};

const loadValidators = async () => {
  try {
    const response = await axios.get('/api/validators');
    validators.value = response.data;
  } catch (err) {
    console.error('Error loading validators:', err);
  }
};

const loadBatteriesAndHarnesses = async () => {
  try {
    const [batteriesResponse, harnessesResponse] = await Promise.all([
      axios.get('/api/v1/test-batteries'),
      axios.get('/api/v1/test-harnesses'),
    ]);
    testBatteries.value = batteriesResponse.data || [];
    testHarnesses.value = harnessesResponse.data || [];
  } catch (err) {
    console.error('Error loading batteries and harnesses:', err);
    testBatteries.value = [];
    testHarnesses.value = [];
  }
};

onMounted(async () => {
  await Promise.all([loadValidators(), loadReports(), loadBatteriesAndHarnesses()]);
});
</script>

<style scoped>
.reports-page {
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

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  color: var(--color-bg-primary);
  border: none;
  border-radius: var(--border-radius-lg);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-primary:disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.filters {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.search-input,
.filter-date {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
  transition: var(--transition-all);
}

.search-input {
  flex: 1;
  min-width: 200px;
}

.filter-dropdown,
.filter-date {
  min-width: 150px;
}

.search-input:focus,
.filter-date:focus {
  outline: none;
  border-color: var(--color-primary);
  box-shadow: 0 0 0 3px var(--border-color-muted);
}

.reports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: var(--spacing-lg);
}

.report-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.report-card:hover {
  transform: translateY(-4px);
  border-color: var(--border-color-primary-hover);
  box-shadow: var(--shadow-lg);
}

.report-header {
  margin-bottom: var(--spacing-xl);
}

.report-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
}

.report-name {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.report-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.status-completed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.status-generating {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.report-meta {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.report-info {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.info-value {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.format-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
}

.format-json {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.format-html {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.format-xml {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.score {
  font-weight: var(--font-weight-semibold);
}

.score-high {
  color: var(--color-success);
}

.score-medium {
  color: var(--color-warning);
}

.score-low {
  color: var(--color-error);
}

.report-summary {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-md);
}

.summary-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.summary-icon {
  width: 16px;
  height: 16px;
}

.summary-icon.passed {
  color: var(--color-success);
}

.summary-icon.failed {
  color: var(--color-error);
}

.report-actions {
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
  flex: 1;
  justify-content: center;
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

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  backdrop-filter: blur(4px);
  z-index: var(--z-index-modal);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: var(--shadow-xl);
}

.report-viewer {
  max-width: 1200px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header-actions {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.action-btn-header {
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

.action-btn-header:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
  max-height: calc(90vh - 100px);
  overflow-y: auto;
}

.report-summary-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: var(--spacing-md);
}

.summary-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  text-align: center;
}

.summary-card-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-sm);
}

.summary-card-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.summary-card-value.passed {
  color: var(--color-success);
}

.summary-card-value.failed {
  color: var(--color-error);
}

.charts-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.charts-section h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xl);
}

.chart-container {
  width: 100%;
}

.score-bars {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.score-bar-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.score-bar-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}

.score-bar {
  position: relative;
  width: 100%;
  height: 32px;
  background: var(--color-bg-overlay-dark);
  border-radius: var(--border-radius-md);
  overflow: hidden;
  display: flex;
  align-items: center;
}

.score-bar-fill {
  position: absolute;
  left: 0;
  top: 0;
  height: 100%;
  border-radius: var(--border-radius-md);
  transition: width 0.3s ease;
}

.score-bar-fill.score-high {
  background: linear-gradient(90deg, var(--color-success) 0%, var(--color-success-dark) 100%);
}

.score-bar-fill.score-medium {
  background: linear-gradient(90deg, var(--color-warning) 0%, var(--color-warning-dark) 100%);
}

.score-bar-fill.score-low {
  background: linear-gradient(90deg, var(--color-error) 0%, var(--color-error-dark) 100%);
}

.score-bar-value {
  position: relative;
  z-index: 1;
  padding: 0 var(--spacing-sm);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.report-content-section {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
}

.report-content-section h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-md);
}

.report-loading {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.loading-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.html-report {
  color: var(--color-text-primary);
}

.json-report {
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  overflow-x: auto;
}

.json-report pre {
  margin: 0;
  color: var(--color-text-secondary);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
  line-height: 1.6;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.validator-badges {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
}

.validator-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  background: var(--border-color-muted);
  color: var(--color-primary);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}
</style>
