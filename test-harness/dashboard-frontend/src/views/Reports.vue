<template>
  <div class="reports-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Reports</h1>
          <p class="page-description">View and download compliance reports</p>
        </div>
        <button @click="generateReport" class="btn-primary" :disabled="isGenerating">
          <FileText class="btn-icon" />
          {{ isGenerating ? 'Generating...' : 'Generate Report' }}
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

    <!-- Reports List -->
    <div class="reports-grid">
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
      <button @click="generateReport" class="btn-primary">
        Generate Report
      </button>
    </div>

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
              <button @click="closeViewer" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="viewingReport?.format === 'html'" class="html-report" v-html="viewingReport.content"></div>
              <div v-else class="json-report">
                <pre>{{ JSON.stringify(viewingReport?.content, null, 2) }}</pre>
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

const breadcrumbItems = [
  { label: 'Reports', icon: FileText }
];

const searchQuery = ref('');
const filterFormat = ref('');
const filterApplication = ref('');
const filterTeam = ref('');
const filterDateFrom = ref('');
const filterDateTo = ref('');
const isGenerating = ref(false);
const viewingReport = ref<any>(null);

// Mock reports data
const reports = ref([
  {
    id: '1',
    name: 'Compliance Report - Q4 2024',
    application: 'research-tracker-api',
    team: 'research-platform',
    format: 'html',
    status: 'completed',
    generatedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
    complianceScore: 95,
    testCount: 24,
    passedTests: 23,
    failedTests: 1
  },
  {
    id: '2',
    name: 'User Service Compliance Report',
    application: 'user-service',
    team: 'platform-team',
    format: 'json',
    status: 'completed',
    generatedAt: new Date(Date.now() - 5 * 60 * 60 * 1000),
    complianceScore: 72,
    testCount: 18,
    passedTests: 13,
    failedTests: 5
  },
  {
    id: '3',
    name: 'Data Pipeline Compliance Report',
    application: 'data-pipeline',
    team: 'data-engineering',
    format: 'xml',
    status: 'generating',
    generatedAt: new Date(Date.now() - 10 * 60 * 1000),
    complianceScore: 0,
    testCount: 0,
    passedTests: 0,
    failedTests: 0
  }
]);

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

const filteredReports = computed(() => {
  return reports.value.filter(report => {
    const matchesSearch = report.name.toLowerCase().includes(searchQuery.value.toLowerCase());
    const matchesFormat = !filterFormat.value || report.format === filterFormat.value;
    const matchesApp = !filterApplication.value || report.application === filterApplication.value;
    const matchesTeam = !filterTeam.value || report.team === filterTeam.value;
    const matchesDate = (!filterDateFrom.value || new Date(report.generatedAt) >= new Date(filterDateFrom.value)) &&
                       (!filterDateTo.value || new Date(report.generatedAt) <= new Date(filterDateTo.value));
    return matchesSearch && matchesFormat && matchesApp && matchesTeam && matchesDate;
  });
});

const generateReport = async () => {
  isGenerating.value = true;
  try {
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const newReport = {
      id: String(reports.value.length + 1),
      name: `Compliance Report - ${new Date().toLocaleDateString()}`,
      application: 'research-tracker-api',
      team: 'research-platform',
      format: 'html',
      status: 'completed',
      generatedAt: new Date(),
      complianceScore: 92,
      testCount: 20,
      passedTests: 19,
      failedTests: 1
    };
    
    reports.value.unshift(newReport);
  } catch (error) {
    console.error('Failed to generate report:', error);
  } finally {
    isGenerating.value = false;
  }
};

const viewReport = (id: string) => {
  const report = reports.value.find(r => r.id === id);
  if (report) {
    viewingReport.value = {
      ...report,
      content: report.format === 'html' 
        ? '<h1>Compliance Report</h1><p>Report content would be displayed here...</p>'
        : { summary: 'Report data', scores: { overall: report.complianceScore } }
    };
  }
};

const closeViewer = () => {
  viewingReport.value = null;
};

const downloadReport = (id: string, format: string) => {
  const report = reports.value.find(r => r.id === id);
  if (report) {
    // Simulate download
    const blob = new Blob([`Report content for ${report.name}`], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.name}.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }
};

const deleteReport = (id: string) => {
  if (confirm('Are you sure you want to delete this report?')) {
    const index = reports.value.findIndex(r => r.id === id);
    if (index !== -1) {
      reports.value.splice(index, 1);
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
</style>
