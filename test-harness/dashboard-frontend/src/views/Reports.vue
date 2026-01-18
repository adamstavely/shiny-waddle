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

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
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

.search-input,
.filter-date {
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

.filter-dropdown,
.filter-date {
  min-width: 150px;
}

.search-input:focus,
.filter-date:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.reports-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
}

.report-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  cursor: pointer;
  transition: all 0.3s;
}

.report-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.report-header {
  margin-bottom: 20px;
}

.report-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.report-name {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.report-status {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-generating {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.report-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.report-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
}

.info-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.format-badge {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.format-json {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.format-html {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.format-xml {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.score {
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

.report-summary {
  display: flex;
  gap: 16px;
  margin-bottom: 16px;
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

.report-actions {
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
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.report-viewer {
  max-width: 1200px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header-actions {
  display: flex;
  align-items: center;
  gap: 12px;
}

.action-btn-header {
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

.action-btn-header:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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
  max-height: calc(90vh - 100px);
  overflow-y: auto;
}

.report-summary-section {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.summary-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.summary-card-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.summary-card-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
}

.summary-card-value.passed {
  color: #22c55e;
}

.summary-card-value.failed {
  color: #fc8181;
}

.charts-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.charts-section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
}

.chart-container {
  width: 100%;
}

.score-bars {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.score-bar-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.score-bar-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
}

.score-bar {
  position: relative;
  width: 100%;
  height: 32px;
  background: rgba(15, 20, 25, 0.8);
  border-radius: 8px;
  overflow: hidden;
  display: flex;
  align-items: center;
}

.score-bar-fill {
  position: absolute;
  left: 0;
  top: 0;
  height: 100%;
  border-radius: 8px;
  transition: width 0.3s ease;
}

.score-bar-fill.score-high {
  background: linear-gradient(90deg, #22c55e 0%, #16a34a 100%);
}

.score-bar-fill.score-medium {
  background: linear-gradient(90deg, #fbbf24 0%, #f59e0b 100%);
}

.score-bar-fill.score-low {
  background: linear-gradient(90deg, #fc8181 0%, #ef4444 100%);
}

.score-bar-value {
  position: relative;
  z-index: 1;
  padding: 0 12px;
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
}

.report-content-section {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.report-content-section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.report-loading {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.loading-state {
  text-align: center;
  padding: 80px 40px;
  color: #a0aec0;
}

.html-report {
  color: #ffffff;
}

.json-report {
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
}

.json-report pre {
  margin: 0;
  color: #a0aec0;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
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
  gap: 6px;
}

.validator-badge {
  padding: 4px 10px;
  border-radius: 6px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  font-size: 0.75rem;
  font-weight: 500;
}
</style>
