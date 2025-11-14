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
  { label: 'Data Behavior', value: 'data-behavior' },
  { label: 'Contract', value: 'contract' },
  { label: 'Dataset Health', value: 'dataset-health' }
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
    return matchesSuite && matchesHarness && matchesBattery && matchesApplication && matchesStatus && matchesType;
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
    const response = await axios.get('/api/test-suites');
    testSuites.value = response.data || [];
  } catch (err) {
    console.error('Error loading test suites:', err);
  }
};

const loadTestHarnesses = async () => {
  try {
    const response = await axios.get('/api/test-harnesses');
    testHarnesses.value = response.data || [];
  } catch (err) {
    console.error('Error loading test harnesses:', err);
  }
};

const loadTestBatteries = async () => {
  try {
    const response = await axios.get('/api/test-batteries');
    testBatteries.value = response.data || [];
  } catch (err) {
    console.error('Error loading test batteries:', err);
  }
};

const loadApplications = async () => {
  try {
    const response = await axios.get('/api/applications');
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
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 2rem;
}

.header-content {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 1.5rem;
}

.page-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 0.5rem 0;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.view-tabs {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 2rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.view-tab {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem 1.5rem;
  background: transparent;
  border: none;
  border-bottom: 2px solid transparent;
  color: #a0aec0;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.view-tab:hover {
  color: #ffffff;
}

.view-tab.active {
  color: #4facfe;
  border-bottom-color: #4facfe;
}

.tab-icon {
  width: 16px;
  height: 16px;
}

.results-filters {
  display: flex;
  gap: 1rem;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
}

.filter-dropdown {
  min-width: 150px;
}

.results-list {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.result-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  cursor: pointer;
  transition: all 0.2s;
}

.result-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.result-header {
  margin-bottom: 1rem;
}

.result-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 0.5rem;
  gap: 1rem;
}

.result-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.result-status {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 500;
}

.result-status.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.result-status.status-failed {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.result-meta {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
  color: #a0aec0;
  font-size: 0.875rem;
}

.result-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
  background: rgba(239, 68, 68, 0.1);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 8px;
  color: #ef4444;
  font-size: 0.875rem;
  margin-bottom: 1rem;
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
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  border-radius: 8px;
  font-size: 0.75rem;
  font-weight: 500;
}

.risk-badge.risk-pending {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.risk-badge.risk-accepted {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.risk-badge.risk-rejected {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.remediation-badge.remediation-in-progress {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.remediation-badge.remediation-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
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
  gap: 0.5rem;
  color: #4facfe;
  font-size: 0.875rem;
}

.ticket-link a {
  color: #4facfe;
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
  gap: 0.5rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-icon {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  padding: 0.5rem;
  cursor: pointer;
  color: #4facfe;
  transition: all 0.2s;
}

.btn-icon:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.btn-icon.btn-warning {
  color: #f59e0b;
  border-color: rgba(245, 158, 11, 0.2);
}

.btn-icon.btn-warning:hover {
  background: rgba(245, 158, 11, 0.1);
  border-color: rgba(245, 158, 11, 0.4);
}

.btn-icon.btn-danger {
  color: #ef4444;
  border-color: rgba(239, 68, 68, 0.2);
}

.btn-icon.btn-danger:hover {
  background: rgba(239, 68, 68, 0.1);
  border-color: rgba(239, 68, 68, 0.4);
}

.btn-icon .icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 4rem 2rem;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 1rem;
  opacity: 0.5;
}

.empty-state h3 {
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.empty-state p {
  color: #a0aec0;
}

.timeline-view {
  margin-top: 2rem;
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
  gap: 0.75rem;
  margin-bottom: 1.5rem;
  padding-bottom: 0.75rem;
  border-bottom: 2px solid rgba(79, 172, 254, 0.2);
}

.date-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.timeline-date-header h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.date-count {
  color: #a0aec0;
  font-size: 0.875rem;
  margin-left: auto;
}

.timeline-items {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  padding-left: 2rem;
  border-left: 2px solid rgba(79, 172, 254, 0.2);
}

.timeline-item {
  display: flex;
  gap: 1rem;
  position: relative;
  padding-left: 1rem;
}

.timeline-item::before {
  content: '';
  position: absolute;
  left: -1.5rem;
  top: 0.5rem;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  background: rgba(79, 172, 254, 0.3);
  border: 2px solid rgba(79, 172, 254, 0.5);
}

.timeline-item.passed::before {
  background: rgba(34, 197, 94, 0.3);
  border-color: rgba(34, 197, 94, 0.5);
}

.timeline-item.failed::before {
  background: rgba(239, 68, 68, 0.3);
  border-color: rgba(239, 68, 68, 0.5);
}

.timeline-marker {
  flex-shrink: 0;
}

.marker-icon {
  width: 20px;
  height: 20px;
}

.marker-icon {
  color: #4facfe;
}

.timeline-item.passed .marker-icon {
  color: #22c55e;
}

.timeline-item.failed .marker-icon {
  color: #ef4444;
}

.timeline-content {
  flex: 1;
}

.timeline-time {
  color: #a0aec0;
  font-size: 0.75rem;
  margin-bottom: 0.25rem;
}

.timeline-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.5rem;
}

.timeline-meta {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  margin-bottom: 0.5rem;
}

.timeline-type,
.timeline-validator {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.timeline-error {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem;
  background: rgba(239, 68, 68, 0.1);
  border-radius: 6px;
  color: #ef4444;
  font-size: 0.875rem;
  margin-top: 0.5rem;
}

.error-icon-small {
  width: 14px;
  height: 14px;
}

.timeline-actions {
  margin-top: 0.5rem;
}

.btn-link {
  background: transparent;
  border: none;
  color: #4facfe;
  font-size: 0.875rem;
  cursor: pointer;
  text-decoration: underline;
}

.btn-link:hover {
  color: #00f2fe;
}

/* Modal Styles */
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.7);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: rgba(26, 31, 46, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  max-width: 600px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 0.5rem;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #ffffff;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 1.5rem;
}

.form-group {
  margin-bottom: 1.5rem;
}

.form-group label {
  display: block;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
  margin-bottom: 0.5rem;
}

.form-input,
.form-textarea {
  width: 100%;
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: inherit;
}

.form-input:focus,
.form-textarea:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.4);
}

.form-textarea {
  resize: vertical;
  min-height: 100px;
}

.result-summary {
  padding: 0.75rem;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.result-summary strong {
  color: #ffffff;
  flex: 1;
}

.result-type-badge {
  padding: 0.25rem 0.75rem;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  font-size: 0.75rem;
  color: #4facfe;
}

.progress-bar-container {
  width: 100%;
  height: 8px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 4px;
  margin-top: 0.5rem;
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s;
}

.form-actions {
  display: flex;
  gap: 1rem;
  justify-content: flex-end;
  margin-top: 2rem;
}

.btn-primary,
.btn-secondary {
  padding: 0.75rem 1.5rem;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  color: #ffffff;
}

.btn-primary:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
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

