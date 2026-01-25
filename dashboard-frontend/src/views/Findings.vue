<template>
  <div class="findings-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Findings</h1>
          <p class="page-description">View and manage test results and findings from CI/CD runs</p>
        </div>
      </div>
    </div>
    
    <!-- View Toggle -->
    <div class="view-tabs">
      <button 
        @click="findingsView = 'list'"
        class="view-tab"
        :class="{ active: findingsView === 'list' }"
      >
        <FileText class="tab-icon" />
        List View
      </button>
      <button 
        @click="findingsView = 'timeline'"
        class="view-tab"
        :class="{ active: findingsView === 'timeline' }"
      >
        <Clock class="tab-icon" />
        Timeline
      </button>
    </div>

    <!-- List View -->
    <div v-if="findingsView === 'list'">
      <div class="results-filters">
        <Dropdown
          v-model="resultsFilterSuite"
          :options="testSuiteOptions"
          placeholder="All Test Suites"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterHarness"
          :options="harnessFilterOptions"
          placeholder="All Harnesses"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterBattery"
          :options="batteryFilterOptions"
          placeholder="All Batteries"
          class="filter-dropdown"
        />
        <Dropdown
          v-model="resultsFilterApplication"
          :options="applicationFilterOptions"
          placeholder="All Applications"
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
        <Dropdown
          v-model="resultsFilterDomain"
          :options="resultsDomainOptions"
          placeholder="All Domains"
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
              <span v-if="result.validatorName" class="result-validator">{{ result.validatorName }}</span>
              <span class="result-time">{{ formatRelativeTime(result.timestamp) }}</span>
            </div>
          </div>
          <div v-if="result.error" class="result-error">
            <AlertTriangle class="error-icon" />
            <span>{{ result.error }}</span>
          </div>
          <div v-if="!result.passed" class="result-risk-management">
            <div v-if="result.riskStatus" class="risk-badge" :class="`risk-${result.riskStatus}`">
              <Shield v-if="result.riskStatus === 'accepted'" class="badge-icon" />
              <AlertCircle v-else-if="result.riskStatus === 'pending'" class="badge-icon" />
              <CheckCircle v-else-if="result.riskStatus === 'remediated'" class="badge-icon" />
              {{ getRiskStatusLabel(result.riskStatus) }}
            </div>
            <div v-if="result.remediationStatus" class="remediation-badge" :class="`remediation-${result.remediationStatus}`">
              <Wrench class="badge-icon" />
              {{ getRemediationStatusLabel(result.remediationStatus) }}
              <span v-if="result.remediationProgress !== undefined" class="progress-text">
                ({{ result.remediationProgress }}%)
              </span>
            </div>
            <div v-if="result.ticketId" class="ticket-link">
              <ExternalLink class="ticket-icon" />
              <a :href="result.ticketUrl" target="_blank" @click.stop>{{ result.ticketId }}</a>
            </div>
          </div>
          <div class="result-actions" @click.stop>
            <button 
              v-if="!result.passed && !result.riskStatus" 
              @click="openRiskAcceptanceModal(result)" 
              class="btn-icon btn-warning" 
              title="Accept Risk"
            >
              <Shield class="icon" />
            </button>
            <button 
              v-if="!result.passed && !result.ticketId" 
              @click="openTicketLinkModal(result)" 
              class="btn-icon btn-secondary" 
              title="Link Ticket"
            >
              <ExternalLink class="icon" />
            </button>
            <button 
              v-if="!result.passed && !result.remediationStatus" 
              @click="openRemediationModal(result)" 
              class="btn-icon btn-primary" 
              title="Start Remediation"
            >
              <Wrench class="icon" />
            </button>
            <button 
              v-if="!result.passed && result.remediationStatus === 'in-progress'" 
              @click="openRemediationModal(result)" 
              class="btn-icon btn-primary" 
              title="Update Remediation"
            >
              <Wrench class="icon" />
            </button>
            <button @click="deleteTestResult(result.id)" class="btn-icon btn-danger" title="Delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>
      </div>

      <div v-if="filteredResults.length === 0" class="empty-state">
        <FileText class="empty-icon" />
        <h3>No test results found</h3>
        <p>Test results will appear here after CI/CD runs</p>
      </div>
    </div>

    <!-- Timeline View -->
    <div v-if="findingsView === 'timeline'" class="timeline-view">
      <div class="timeline-container">
        <div
          v-for="(group, index) in timelineGroups"
          :key="index"
          class="timeline-group"
        >
          <div class="timeline-date-header">
            <Clock class="date-icon" />
            <h3>{{ group.date }}</h3>
            <span class="date-count">{{ group.results.length }} result(s)</span>
          </div>
          <div class="timeline-items">
            <div
              v-for="result in group.results"
              :key="result.id"
              class="timeline-item"
              :class="{ 'passed': result.passed, 'failed': !result.passed }"
            >
              <div class="timeline-marker">
                <CheckCircle v-if="result.passed" class="marker-icon" />
                <XCircle v-else class="marker-icon" />
              </div>
              <div class="timeline-content">
                <div class="timeline-time">{{ formatTime(result.timestamp) }}</div>
                <div class="timeline-title">{{ result.testName }}</div>
                <div class="timeline-meta">
                  <span class="timeline-type">{{ result.testType }}</span>
                  <span v-if="result.validatorName" class="timeline-validator">{{ result.validatorName }}</span>
                </div>
                <div v-if="result.error" class="timeline-error">
                  <AlertTriangle class="error-icon-small" />
                  {{ result.error }}
                </div>
                <div v-if="!result.passed" class="timeline-actions">
                  <button @click="viewResultDetails(result.id)" class="btn-link">View Details</button>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div v-if="timelineGroups.length === 0" class="empty-state">
          <Clock class="empty-icon" />
          <h3>No test execution history</h3>
          <p>Test runs will appear here in chronological order</p>
        </div>
      </div>
    </div>
    
    <!-- Test Result Detail Modal -->
    <TestResultDetailModal
      :show="showResultDetail"
      :result="selectedResult"
      :previous-result="previousResult"
      @close="closeResultDetail"
      @export="exportTestResult"
    />

    <!-- Risk Acceptance Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showRiskAcceptanceModal" class="modal-overlay" @click="closeRiskAcceptanceModal">
          <div class="modal-content risk-modal" @click.stop>
            <div class="modal-header">
              <h2>Request Risk Acceptance</h2>
              <button @click="closeRiskAcceptanceModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForRisk" class="risk-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForRisk.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForRisk.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="risk-reason">Reason for Risk Acceptance *</label>
                  <textarea
                    id="risk-reason"
                    v-model="riskReason"
                    rows="3"
                    placeholder="Explain why this risk should be accepted..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-group">
                  <label for="risk-justification">Justification *</label>
                  <textarea
                    id="risk-justification"
                    v-model="riskJustification"
                    rows="3"
                    placeholder="Provide business or technical justification..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeRiskAcceptanceModal" class="btn-secondary">Cancel</button>
                  <button @click="handleSubmitRiskAcceptance" class="btn-primary">Submit Request</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Ticket Link Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showTicketLinkModal" class="modal-overlay" @click="closeTicketLinkModal">
          <div class="modal-content ticket-modal" @click.stop>
            <div class="modal-header">
              <h2>Link Ticket</h2>
              <button @click="closeTicketLinkModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForTicket" class="ticket-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForTicket.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForTicket.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="ticket-id">Ticket ID *</label>
                  <input
                    id="ticket-id"
                    v-model="ticketId"
                    type="text"
                    placeholder="e.g., JIRA-123, GH-456"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label for="ticket-url">Ticket URL (optional)</label>
                  <input
                    id="ticket-url"
                    v-model="ticketUrl"
                    type="url"
                    placeholder="https://..."
                    class="form-input"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeTicketLinkModal" class="btn-secondary">Cancel</button>
                  <button @click="submitTicketLink" class="btn-primary">Link Ticket</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>

    <!-- Remediation Tracking Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showRemediationModal" class="modal-overlay" @click="closeRemediationModal">
          <div class="modal-content remediation-modal" @click.stop>
            <div class="modal-header">
              <h2>Remediation Tracking</h2>
              <button @click="closeRemediationModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <div v-if="selectedResultForRemediation" class="remediation-form">
                <div class="form-group">
                  <label>Test Result</label>
                  <div class="result-summary">
                    <strong>{{ selectedResultForRemediation.testName }}</strong>
                    <span class="result-type-badge">{{ selectedResultForRemediation.testType }}</span>
                  </div>
                </div>
                <div class="form-group">
                  <label for="remediation-progress">Progress (%)</label>
                  <input
                    id="remediation-progress"
                    v-model.number="remediationProgress"
                    type="number"
                    min="0"
                    max="100"
                    class="form-input"
                  />
                  <div class="progress-bar-container">
                    <div class="progress-bar" :style="{ width: `${remediationProgress}%` }"></div>
                  </div>
                </div>
                <div class="form-group">
                  <label for="remediation-step">Current Step</label>
                  <input
                    id="remediation-step"
                    v-model="remediationCurrentStep"
                    type="text"
                    placeholder="e.g., Fixing access control policy..."
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label for="remediation-notes">Notes</label>
                  <textarea
                    id="remediation-notes"
                    v-model="remediationNotes"
                    rows="4"
                    placeholder="Add notes about remediation progress..."
                    class="form-textarea"
                  />
                </div>
                <div class="form-actions">
                  <button @click="closeRemediationModal" class="btn-secondary">Cancel</button>
                  <button 
                    v-if="remediationProgress === 100"
                    @click="completeRemediation"
                    class="btn-primary"
                  >
                    Mark Complete
                  </button>
                  <button @click="submitRemediation" class="btn-primary">Update Progress</button>
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
import { ref, computed, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { Teleport, Transition } from 'vue';
import {
  FileText,
  Clock,
  AlertTriangle,
  Shield,
  CheckCircle,
  XCircle,
  ExternalLink,
  Wrench,
  Trash2,
  X
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import TestResultDetailModal from '../components/TestResultDetailModal.vue';

const router = useRouter();
const route = useRoute();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' },
  { label: 'Findings' }
];

const findingsView = ref<'list' | 'timeline'>('list');
const testResults = ref<any[]>([]);
const testSuites = ref<any[]>([]);
const testHarnesses = ref<any[]>([]);
const testBatteries = ref<any[]>([]);
const applicationsList = ref<any[]>([]);

const resultsFilterSuite = ref('');
const resultsFilterHarness = ref('');
const resultsFilterBattery = ref('');
const resultsFilterApplication = ref('');
const resultsFilterStatus = ref('');
const resultsFilterType = ref('');
const resultsFilterDomain = ref('');

const showResultDetail = ref(false);
const selectedResult = ref<any>(null);
const previousResult = ref<any>(null);

const showRiskAcceptanceModal = ref(false);
const selectedResultForRisk = ref<any>(null);
const riskReason = ref('');
const riskJustification = ref('');

const showTicketLinkModal = ref(false);
const selectedResultForTicket = ref<any>(null);
const ticketId = ref('');
const ticketUrl = ref('');

const showRemediationModal = ref(false);
const selectedResultForRemediation = ref<any>(null);
const remediationProgress = ref(0);
const remediationCurrentStep = ref('');
const remediationNotes = ref('');

const testSuiteOptions = computed(() => {
  return [
    { label: 'All Test Suites', value: '' },
    ...testSuites.value.map(s => ({ label: s.name, value: s.id }))
  ];
});

const harnessFilterOptions = computed(() => {
  return [
    { label: 'All Harnesses', value: '' },
    ...testHarnesses.value.map(h => ({ label: h.name, value: h.id }))
  ];
});

const batteryFilterOptions = computed(() => {
  return [
    { label: 'All Batteries', value: '' },
    ...testBatteries.value.map(b => ({ label: b.name, value: b.id }))
  ];
});

const applicationFilterOptions = computed(() => {
  return [
    { label: 'All Applications', value: '' },
    ...applicationsList.value.map(a => ({ label: a.name, value: a.id }))
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
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' }
]);

const resultsDomainOptions = computed(() => [
  { label: 'All Domains', value: '' },
  { label: 'API Security', value: 'api_security' },
  { label: 'Platform Configuration', value: 'platform_config' },
  { label: 'Identity', value: 'identity' },
  { label: 'Data Contracts', value: 'data_contracts' },
  { label: 'Salesforce', value: 'salesforce' },
  { label: 'Elastic', value: 'elastic' },
  { label: 'IDP / Kubernetes', value: 'idp_platform' },
]);

const filteredResults = computed(() => {
  if (!testResults.value) return [];
  return testResults.value.filter(result => {
    const matchesSuite = !resultsFilterSuite.value || (result.testSuiteId === resultsFilterSuite.value);
    const matchesHarness = !resultsFilterHarness.value || 
      (result.harnessId === resultsFilterHarness.value || 
       (result.harnessIds && result.harnessIds.includes(resultsFilterHarness.value)));
    const matchesBattery = !resultsFilterBattery.value ||
      (result.batteryId === resultsFilterBattery.value ||
       (result.batteryIds && result.batteryIds.includes(resultsFilterBattery.value)));
    const matchesApplication = !resultsFilterApplication.value ||
      (result.applicationId === resultsFilterApplication.value ||
       (result.application && result.application === resultsFilterApplication.value));
    const matchesStatus = !resultsFilterStatus.value ||
      (resultsFilterStatus.value === 'passed' && result.passed) ||
      (resultsFilterStatus.value === 'failed' && !result.passed);
    const matchesType = !resultsFilterType.value || result.testType === resultsFilterType.value;
    const matchesDomain = !resultsFilterDomain.value || result.domain === resultsFilterDomain.value;
    return matchesSuite && matchesHarness && matchesBattery && matchesApplication && matchesStatus && matchesType && matchesDomain;
  });
});

const timelineGroups = computed(() => {
  if (!filteredResults.value || filteredResults.value.length === 0) return [];
  
  const groups = new Map<string, any[]>();
  
  filteredResults.value.forEach(result => {
    const date = new Date(result.timestamp);
    const dateKey = date.toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
    
    if (!groups.has(dateKey)) {
      groups.set(dateKey, []);
    }
    groups.get(dateKey)!.push(result);
  });
  
  return Array.from(groups.entries())
    .map(([date, results]) => ({
      date,
      results: results.sort((a, b) => 
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ),
    }))
    .sort((a, b) => 
      new Date(b.date).getTime() - new Date(a.date).getTime()
    );
});

const formatTime = (timestamp: Date | string): string => {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  return date.toLocaleTimeString('en-US', { 
    hour: '2-digit', 
    minute: '2-digit' 
  });
};

const formatRelativeTime = (date: Date | undefined): string => {
  if (!date) return 'Never';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMs / 3600000);
  if (diffHours < 24) return `${diffHours}h ago`;
  return date.toLocaleDateString();
};

const getRiskStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    'pending': 'Risk Acceptance Pending',
    'accepted': 'Risk Accepted',
    'rejected': 'Risk Rejected',
    'remediated': 'Remediated',
  };
  return labels[status] || status;
};

const getRemediationStatusLabel = (status: string): string => {
  const labels: Record<string, string> = {
    'not-started': 'Not Started',
    'in-progress': 'In Progress',
    'completed': 'Completed',
    'verified': 'Verified',
  };
  return labels[status] || status;
};

const loadTestResults = async () => {
  try {
    const response = await axios.get('/api/test-results?limit=1000');
    if (response.data) {
      testResults.value = response.data.map((r: any) => ({
        ...r,
        timestamp: r.timestamp ? new Date(r.timestamp) : new Date(),
        passed: r.status === 'passed'
      }));
    }
  } catch (err) {
    console.error('Error loading test results:', err);
  }
};

const loadTestSuites = async () => {
  try {
    const response = await axios.get('/api/v1/test-suites');
    testSuites.value = response.data || [];
  } catch (err) {
    console.error('Error loading test suites:', err);
  }
};

const loadTestHarnesses = async () => {
  try {
    const response = await axios.get('/api/v1/test-harnesses');
    testHarnesses.value = response.data || [];
  } catch (err) {
    console.error('Error loading test harnesses:', err);
  }
};

const loadTestBatteries = async () => {
  try {
    const response = await axios.get('/api/v1/test-batteries');
    testBatteries.value = response.data || [];
  } catch (err) {
    console.error('Error loading test batteries:', err);
  }
};

const loadApplications = async () => {
  try {
    const response = await axios.get("/api/v1/applications");
    applicationsList.value = response.data || [];
  } catch (err) {
    console.error('Error loading applications:', err);
  }
};

const viewResultDetails = (id: string) => {
  const result = testResults.value.find(r => r.id === id);
  if (result) {
    selectedResult.value = result;
    const previous = testResults.value
      .filter(r => r.testName === result.testName && r.id !== id)
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())[0];
    previousResult.value = previous || null;
    showResultDetail.value = true;
  }
};

const closeResultDetail = () => {
  showResultDetail.value = false;
  selectedResult.value = null;
  previousResult.value = null;
};

const exportTestResult = (result: any) => {
  const dataStr = JSON.stringify(result, null, 2);
  const dataBlob = new Blob([dataStr], { type: 'application/json' });
  const url = URL.createObjectURL(dataBlob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `test-result-${result.id}.json`;
  link.click();
  URL.revokeObjectURL(url);
};

const deleteTestResult = async (id: string) => {
  if (!confirm('Are you sure you want to delete this test result? This action cannot be undone.')) {
    return;
  }
  try {
    await axios.delete(`/api/test-results/${id}`);
    const index = testResults.value.findIndex(r => r.id === id);
    if (index !== -1) {
      testResults.value.splice(index, 1);
    }
  } catch (err: any) {
    console.error('Error deleting test result:', err);
    alert(err.response?.data?.message || 'Failed to delete test result');
  }
};

const openRiskAcceptanceModal = (result: any) => {
  selectedResultForRisk.value = result;
  showRiskAcceptanceModal.value = true;
};

const closeRiskAcceptanceModal = () => {
  showRiskAcceptanceModal.value = false;
  selectedResultForRisk.value = null;
  riskReason.value = '';
  riskJustification.value = '';
};

const handleSubmitRiskAcceptance = async () => {
  if (!selectedResultForRisk.value || !riskReason.value || !riskJustification.value) {
    alert('Please provide both reason and justification');
    return;
  }
  
  try {
    await axios.post('/api/finding-approvals/request', {
      findingId: selectedResultForRisk.value.id,
      type: 'risk-acceptance',
      reason: riskReason.value,
      justification: riskJustification.value,
    });
    const index = testResults.value.findIndex(r => r.id === selectedResultForRisk.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        riskStatus: 'pending',
      };
    }
    closeRiskAcceptanceModal();
  } catch (err: any) {
    console.error('Error submitting risk acceptance:', err);
    alert(err.response?.data?.message || 'Failed to submit risk acceptance request');
  }
};

const openTicketLinkModal = (result: any) => {
  selectedResultForTicket.value = result;
  ticketId.value = result.ticketId || '';
  ticketUrl.value = result.ticketUrl || '';
  showTicketLinkModal.value = true;
};

const closeTicketLinkModal = () => {
  showTicketLinkModal.value = false;
  selectedResultForTicket.value = null;
  ticketId.value = '';
  ticketUrl.value = '';
};

const submitTicketLink = async () => {
  if (!selectedResultForTicket.value || !ticketId.value) {
    alert('Please enter a ticket ID');
    return;
  }
  
  try {
    const index = testResults.value.findIndex(r => r.id === selectedResultForTicket.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        ticketId: ticketId.value,
        ticketUrl: ticketUrl.value || `https://tickets.example.com/${ticketId.value}`,
      };
    }
    closeTicketLinkModal();
  } catch (err: any) {
    console.error('Error linking ticket:', err);
    alert(err.response?.data?.message || 'Failed to link ticket');
  }
};

const openRemediationModal = async (result: any) => {
  selectedResultForRemediation.value = result;
  
  try {
    const response = await axios.get(`/api/remediation-tracking/violation/${result.id}`);
    if (response.data) {
      remediationProgress.value = response.data.progress || 0;
      remediationCurrentStep.value = response.data.currentStep || '';
      remediationNotes.value = response.data.notes || '';
    } else {
      remediationProgress.value = 0;
      remediationCurrentStep.value = '';
      remediationNotes.value = '';
    }
  } catch (err) {
    remediationProgress.value = 0;
    remediationCurrentStep.value = '';
    remediationNotes.value = '';
  }
  
  showRemediationModal.value = true;
};

const closeRemediationModal = () => {
  showRemediationModal.value = false;
  selectedResultForRemediation.value = null;
  remediationProgress.value = 0;
  remediationCurrentStep.value = '';
  remediationNotes.value = '';
};

const submitRemediation = async () => {
  if (!selectedResultForRemediation.value) return;
  
  try {
    let trackingId = null;
    try {
      const existingResponse = await axios.get(`/api/remediation-tracking/violation/${selectedResultForRemediation.value.id}`);
      if (existingResponse.data) {
        trackingId = existingResponse.data.id;
      }
    } catch (err) {
      // No existing tracking
    }
    
    if (trackingId) {
      await axios.patch(`/api/remediation-tracking/${trackingId}/progress`, {
        progress: remediationProgress.value,
        currentStep: remediationCurrentStep.value,
      });
    } else {
      const response = await axios.post('/api/remediation-tracking', {
        violationId: selectedResultForRemediation.value.id,
        findingId: selectedResultForRemediation.value.id,
        description: `Remediation for ${selectedResultForRemediation.value.testName}`,
      });
      trackingId = response.data.id;
      
      await axios.post(`/api/remediation-tracking/${trackingId}/start`, {
        actor: 'current-user',
      });
      
      if (remediationProgress.value > 0) {
        await axios.patch(`/api/remediation-tracking/${trackingId}/progress`, {
          progress: remediationProgress.value,
          currentStep: remediationCurrentStep.value,
        });
      }
    }
    
    const index = testResults.value.findIndex(r => r.id === selectedResultForRemediation.value.id);
    if (index !== -1) {
      testResults.value[index] = {
        ...testResults.value[index],
        remediationStatus: remediationProgress.value === 100 ? 'completed' : 'in-progress',
        remediationProgress: remediationProgress.value,
      };
    }
    
    closeRemediationModal();
  } catch (err: any) {
    console.error('Error submitting remediation:', err);
    alert(err.response?.data?.message || 'Failed to submit remediation tracking');
  }
};

const completeRemediation = async () => {
  if (!selectedResultForRemediation.value) return;
  
  try {
    let trackingId = null;
    try {
      const existingResponse = await axios.get(`/api/remediation-tracking/violation/${selectedResultForRemediation.value.id}`);
      if (existingResponse.data) {
        trackingId = existingResponse.data.id;
      }
    } catch (err) {
      alert('Remediation tracking not found. Please update progress first.');
      return;
    }
    
    if (trackingId) {
      await axios.post(`/api/remediation-tracking/${trackingId}/complete`, {
        actor: 'current-user',
        effectiveness: 'effective',
      });
      
      const index = testResults.value.findIndex(r => r.id === selectedResultForRemediation.value.id);
      if (index !== -1) {
        testResults.value[index] = {
          ...testResults.value[index],
          remediationStatus: 'completed',
          remediationProgress: 100,
        };
      }
    }
    
    closeRemediationModal();
  } catch (err: any) {
    console.error('Error completing remediation:', err);
    alert(err.response?.data?.message || 'Failed to complete remediation');
  }
};

onMounted(async () => {
  await Promise.all([
    loadTestResults(),
    loadTestSuites(),
    loadTestHarnesses(),
    loadTestBatteries(),
    loadApplications()
  ]);
  
  // Check for query params
  if (route.query.suite) {
    resultsFilterSuite.value = route.query.suite as string;
  }
  if (route.query.result) {
    const resultId = route.query.result as string;
    viewResultDetails(resultId);
  }
});
</script>

<style scoped>
.findings-page {
  padding: var(--spacing-xl);
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
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  color: var(--color-text-secondary);
  margin: 0;
}

.view-tabs {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xl);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.view-tab {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md) var(--spacing-lg);
  background: transparent;
  border: none;
  border-bottom: var(--border-width-medium) solid transparent;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.view-tab:hover {
  color: var(--color-text-primary);
}

.view-tab.active {
  color: var(--color-primary);
  border-bottom-color: var(--color-primary);
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.results-filters {
  display: flex;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  flex-wrap: wrap;
}

.filter-dropdown {
  min-width: 150px;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.result-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg);
  cursor: pointer;
  transition: var(--transition-all);
}

.result-card:hover {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
}

.result-header {
  margin-bottom: var(--spacing-md);
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-sm);
  gap: var(--spacing-md);
}

.result-name {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
  flex: 1;
}

.result-status {
  padding: var(--spacing-xs) var(--spacing-md);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.result-status.status-passed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.result-status.status-failed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.result-meta {
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
}

.result-error {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-radius: var(--border-radius-md);
  color: var(--color-error);
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-md);
}

.error-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.result-risk-management {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-bottom: 1rem;
}

.risk-badge,
.remediation-badge {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-medium);
}

.risk-badge.risk-pending {
  background: var(--color-warning-bg);
  color: var(--color-warning);
}

.risk-badge.risk-accepted {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.risk-badge.risk-rejected {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.remediation-badge.remediation-in-progress {
  background: var(--color-info-bg);
  color: var(--color-primary);
}

.remediation-badge.remediation-completed {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.badge-icon {
  width: 14px;
  height: 14px;
}

.progress-text {
  opacity: 0.8;
}

.ticket-link {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  color: var(--color-primary);
  font-size: var(--font-size-sm);
}

.ticket-link a {
  color: var(--color-primary);
  text-decoration: none;
}

.ticket-link a:hover {
  text-decoration: underline;
}

.ticket-icon {
  width: 14px;
  height: 14px;
}

.result-actions {
  display: flex;
  gap: var(--spacing-sm);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.btn-icon {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  padding: var(--spacing-sm);
  cursor: pointer;
  color: var(--color-primary);
  transition: var(--transition-all);
}

.btn-icon:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.btn-icon.btn-warning {
  color: var(--color-warning);
  border-color: var(--color-warning);
  opacity: 0.2;
}

.btn-icon.btn-warning:hover {
  background: var(--color-warning-bg);
  border-color: var(--color-warning);
}

.btn-icon.btn-danger {
  color: var(--color-error);
  border-color: var(--color-error);
  opacity: 0.2;
}

.btn-icon.btn-danger:hover {
  background: var(--color-error-bg);
  border-color: var(--color-error);
}

.btn-icon .icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 4rem var(--spacing-xl);
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: var(--color-primary);
  margin: 0 auto var(--spacing-md);
  opacity: 0.5;
}

.empty-state h3 {
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.empty-state p {
  color: var(--color-text-secondary);
}

.timeline-view {
  margin-top: var(--spacing-xl);
}

.timeline-container {
  max-width: 800px;
  margin: 0 auto;
}

.timeline-group {
  margin-bottom: 3rem;
}

.timeline-date-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-medium) solid var(--border-color-primary);
}

.date-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
}

.timeline-date-header h3 {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.date-count {
  color: var(--color-text-secondary);
  font-size: var(--font-size-sm);
  margin-left: auto;
}

.timeline-items {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding-left: var(--spacing-xl);
  border-left: var(--border-width-medium) solid var(--border-color-primary);
}

.timeline-item {
  display: flex;
  gap: var(--spacing-md);
  position: relative;
  padding-left: var(--spacing-md);
}

.timeline-item::before {
  content: '';
  position: absolute;
  left: -1.5rem;
  top: 0.5rem;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: var(--color-info-bg);
  border: var(--border-width-medium) solid var(--color-primary);
}

.timeline-item.passed::before {
  background: var(--color-success-bg);
  border-color: var(--color-success);
}

.timeline-item.failed::before {
  background: var(--color-error-bg);
  border-color: var(--color-error);
}

.timeline-marker {
  flex-shrink: 0;
}

.marker-icon {
  width: 20px;
  height: 20px;
}

.marker-icon {
  color: var(--color-primary);
}

.timeline-item.passed .marker-icon {
  color: var(--color-success);
}

.timeline-item.failed .marker-icon {
  color: var(--color-error);
}

.timeline-content {
  flex: 1;
}

.timeline-time {
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
  margin-bottom: var(--spacing-xs);
}

.timeline-title {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-sm);
}

.timeline-meta {
  display: flex;
  gap: var(--spacing-md);
  flex-wrap: wrap;
  margin-bottom: var(--spacing-sm);
}

.timeline-type,
.timeline-validator {
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--color-info-bg);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.timeline-error {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-error-bg);
  border-radius: var(--border-radius-sm);
  color: var(--color-error);
  font-size: var(--font-size-sm);
  margin-top: var(--spacing-sm);
}

.error-icon-small {
  width: 14px;
  height: 14px;
}

.timeline-actions {
  margin-top: var(--spacing-sm);
}

.btn-link {
  background: transparent;
  border: none;
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
  text-decoration: underline;
}

.btn-link:hover {
  color: var(--color-secondary);
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
}

.modal-content {
  background: var(--color-bg-overlay-dark);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  max-width: 600px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-sm);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: var(--color-text-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
}

.form-group {
  margin-bottom: var(--spacing-lg);
}

.form-group label {
  display: block;
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  margin-bottom: var(--spacing-sm);
}

.form-input,
.form-textarea {
  width: 100%;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-family: inherit;
}

.form-input:focus,
.form-textarea:focus {
  outline: none;
  border-color: var(--border-color-primary-active);
}

.form-textarea {
  resize: vertical;
  min-height: 100px;
}

.result-summary {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.result-summary strong {
  color: var(--color-text-primary);
  flex: 1;
}

.result-type-badge {
  padding: var(--spacing-xs) var(--spacing-md);
  background: var(--color-info-bg);
  border-radius: var(--border-radius-lg);
  font-size: var(--font-size-xs);
  color: var(--color-primary);
}

.progress-bar-container {
  width: 100%;
  height: 8px;
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-xs);
  margin-top: var(--spacing-sm);
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  background: var(--gradient-primary);
  transition: width 0.3s;
}

.form-actions {
  display: flex;
  gap: var(--spacing-md);
  justify-content: flex-end;
  margin-top: var(--spacing-xl);
}

.btn-primary,
.btn-secondary {
  padding: var(--spacing-md) var(--spacing-lg);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-primary {
  background: var(--gradient-primary);
  border: none;
  color: var(--color-text-primary);
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: var(--shadow-primary-hover);
}

.btn-secondary {
  background: transparent;
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-primary);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

