<template>
  <div class="scheduled-reports">
    <div class="reports-header">
      <h3>Scheduled Reports</h3>
      <button @click="showCreateModal = true" class="btn-primary">
        <Plus class="icon" />
        Create Scheduled Report
      </button>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading scheduled reports...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadReports" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="reports.length === 0" class="empty-state">
      <p>No scheduled reports. Create one to get automated policy summaries.</p>
    </div>

    <div v-else class="reports-list">
      <div
        v-for="report in reports"
        :key="report.id"
        class="report-card"
        :class="{ disabled: !report.enabled }"
      >
        <div class="report-header">
          <div>
            <h4>{{ report.name }}</h4>
            <span class="report-type-badge" :class="`type-${report.type}`">
              {{ report.type }}
            </span>
            <span class="report-schedule-badge" :class="`schedule-${report.schedule}`">
              {{ report.schedule }}
            </span>
          </div>
          <div class="report-actions">
            <button @click="toggleReport(report)" class="btn-toggle" :class="{ active: report.enabled }">
              {{ report.enabled ? 'Enabled' : 'Disabled' }}
            </button>
            <button @click="runReportNow(report)" class="btn-run" :disabled="runningReport === report.id">
              {{ runningReport === report.id ? 'Running...' : 'Run Now' }}
            </button>
            <button @click="editReport(report)" class="btn-edit">
              <Edit class="icon" />
            </button>
            <button @click="deleteReport(report)" class="btn-delete">
              <Trash2 class="icon" />
            </button>
          </div>
        </div>

        <div class="report-details">
          <div class="detail-item">
            <strong>Recipients:</strong>
            <span>{{ report.recipients.join(', ') || 'None' }}</span>
          </div>
          <div class="detail-item">
            <strong>Last Run:</strong>
            <span>{{ report.lastRun ? formatDate(report.lastRun) : 'Never' }}</span>
          </div>
          <div class="detail-item">
            <strong>Next Run:</strong>
            <span>{{ formatDate(report.nextRun) }}</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Create/Edit Modal -->
    <div v-if="showCreateModal || editingReport" class="modal-overlay" @click="closeModal">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>{{ editingReport ? 'Edit Report' : 'Create Scheduled Report' }}</h3>
          <button @click="closeModal" class="btn-close">
            <X class="icon" />
          </button>
        </div>

        <form @submit.prevent="saveReport" class="modal-body">
          <div class="form-group">
            <label>Report Name</label>
            <input v-model="reportForm.name" type="text" required />
          </div>

          <div class="form-group">
            <label>Report Type</label>
            <select v-model="reportForm.type" required>
              <option value="executive">Executive Summary</option>
              <option value="detailed">Detailed Summary</option>
              <option value="compliance">Compliance Summary</option>
            </select>
          </div>

          <div class="form-group">
            <label>Schedule</label>
            <select v-model="reportForm.schedule" required>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>

          <div class="form-group">
            <label>Recipients (comma-separated emails)</label>
            <input
              v-model="recipientsInput"
              type="text"
              placeholder="user1@example.com, user2@example.com"
            />
          </div>

          <div class="form-group">
            <label>
              <input v-model="reportForm.enabled" type="checkbox" />
              Enabled
            </label>
          </div>

          <div class="modal-footer">
            <button type="button" @click="closeModal" class="btn-cancel">Cancel</button>
            <button type="submit" class="btn-save">Save</button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { Plus, Edit, Trash2, X, AlertTriangle } from 'lucide-vue-next';
import axios from 'axios';

interface ScheduledReport {
  id: string;
  name: string;
  type: 'executive' | 'detailed' | 'compliance';
  schedule: 'daily' | 'weekly' | 'monthly';
  recipients: string[];
  enabled: boolean;
  lastRun?: Date;
  nextRun: Date;
  templateId?: string;
}

const reports = ref<ScheduledReport[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showCreateModal = ref(false);
const editingReport = ref<ScheduledReport | null>(null);
const runningReport = ref<string | null>(null);

const reportForm = ref<Omit<ScheduledReport, 'id' | 'nextRun'>>({
  name: '',
  type: 'executive',
  schedule: 'daily',
  recipients: [],
  enabled: true,
});

const recipientsInput = ref('');

const loadReports = async () => {
  loading.value = true;
  error.value = null;

  try {
    const response = await axios.get('/api/policies/reports/scheduled');
    reports.value = response.data.map((r: ScheduledReport) => ({
      ...r,
      lastRun: r.lastRun ? new Date(r.lastRun) : undefined,
      nextRun: new Date(r.nextRun),
    }));
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load reports';
    console.error('Error loading reports:', err);
  } finally {
    loading.value = false;
  }
};

const saveReport = async () => {
  try {
    const reportData = {
      ...reportForm.value,
      recipients: recipientsInput.value
        .split(',')
        .map(email => email.trim())
        .filter(email => email.length > 0),
    };

    if (editingReport.value) {
      await axios.patch(`/api/policies/reports/scheduled/${editingReport.value.id}`, reportData);
    } else {
      await axios.post('/api/policies/reports/scheduled', reportData);
    }

    await loadReports();
    closeModal();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to save report';
    console.error('Error saving report:', err);
  }
};

const toggleReport = async (report: ScheduledReport) => {
  try {
    await axios.patch(`/api/policies/reports/scheduled/${report.id}`, {
      enabled: !report.enabled,
    });
    await loadReports();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to toggle report';
    console.error('Error toggling report:', err);
  }
};

const runReportNow = async (report: ScheduledReport) => {
  runningReport.value = report.id;
  try {
    await axios.post(`/api/policies/reports/scheduled/${report.id}/run`);
    await loadReports();
    alert('Report generated and sent successfully');
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to run report';
    console.error('Error running report:', err);
  } finally {
    runningReport.value = null;
  }
};

const editReport = (report: ScheduledReport) => {
  editingReport.value = report;
  reportForm.value = {
    name: report.name,
    type: report.type,
    schedule: report.schedule,
    recipients: report.recipients,
    enabled: report.enabled,
  };
  recipientsInput.value = report.recipients.join(', ');
  showCreateModal.value = true;
};

const deleteReport = async (report: ScheduledReport) => {
  if (!confirm(`Are you sure you want to delete "${report.name}"?`)) {
    return;
  }

  try {
    await axios.delete(`/api/policies/reports/scheduled/${report.id}`);
    await loadReports();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to delete report';
    console.error('Error deleting report:', err);
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingReport.value = null;
  reportForm.value = {
    name: '',
    type: 'executive',
    schedule: 'daily',
    recipients: [],
    enabled: true,
  };
  recipientsInput.value = '';
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
};

onMounted(() => {
  loadReports();
});
</script>

<style scoped>
.scheduled-reports {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.reports-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.reports-header h3 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.icon {
  width: 18px;
  height: 18px;
}

.reports-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.report-card {
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.report-card.disabled {
  opacity: 0.6;
}

.report-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-md);
}

.report-header h4 {
  margin: 0 0 var(--spacing-xs) 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
}

.report-type-badge,
.report-schedule-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  margin-right: var(--spacing-xs);
}

.report-type-badge.type-executive {
  background: var(--color-primary);
  color: white;
}

.report-type-badge.type-detailed {
  background: var(--color-info);
  color: white;
}

.report-type-badge.type-compliance {
  background: var(--color-success);
  color: white;
}

.report-schedule-badge.schedule-daily {
  background: rgba(var(--color-primary-rgb), 0.1);
  color: var(--color-primary);
}

.report-schedule-badge.schedule-weekly {
  background: rgba(var(--color-warning-rgb), 0.1);
  color: var(--color-warning);
}

.report-schedule-badge.schedule-monthly {
  background: rgba(var(--color-info-rgb), 0.1);
  color: var(--color-info);
}

.report-actions {
  display: flex;
  gap: var(--spacing-xs);
}

.btn-toggle,
.btn-run,
.btn-edit,
.btn-delete {
  padding: var(--spacing-xs) var(--spacing-sm);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.btn-toggle.active {
  background: var(--color-success);
  color: white;
  border-color: var(--color-success);
}

.btn-run:hover:not(:disabled) {
  background: var(--color-primary);
  color: white;
  border-color: var(--color-primary);
}

.btn-run:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-edit:hover {
  background: var(--color-info);
  color: white;
  border-color: var(--color-info);
}

.btn-delete:hover {
  background: var(--color-error);
  color: white;
  border-color: var(--color-error);
}

.report-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
}

.detail-item {
  display: flex;
  gap: var(--spacing-sm);
}

.detail-item strong {
  min-width: 100px;
  color: var(--color-text-secondary);
}

.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--color-bg-primary);
  border-radius: var(--border-radius-lg);
  width: 90%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-header h3 {
  margin: 0;
}

.btn-close {
  background: none;
  border: none;
  color: var(--color-text-secondary);
  cursor: pointer;
  padding: var(--spacing-xs);
}

.modal-body {
  padding: var(--spacing-lg);
}

.form-group {
  margin-bottom: var(--spacing-md);
}

.form-group label {
  display: block;
  margin-bottom: var(--spacing-xs);
  font-weight: var(--font-weight-medium);
}

.form-group input,
.form-group select {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-lg);
  padding-top: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-cancel,
.btn-save {
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.btn-cancel {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  color: var(--color-text-primary);
}

.btn-save {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: var(--spacing-xl);
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin: 0 auto var(--spacing-md);
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
}
</style>
