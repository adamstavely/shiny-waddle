<template>
  <div class="scheduled-reports">
    <div class="section-header">
      <h3 class="section-title">Scheduled Reports</h3>
      <button @click="showCreateModal = true" class="btn-primary-small">
        <Clock class="btn-icon" />
        Create Schedule
      </button>
    </div>

    <div v-if="loading" class="loading-state">
      <p>Loading scheduled reports...</p>
    </div>

    <div v-else-if="scheduledReports.length === 0" class="empty-state">
      <Clock class="empty-icon" />
      <p>No scheduled reports</p>
      <button @click="showCreateModal = true" class="btn-primary">
        Create Schedule
      </button>
    </div>

    <div v-else class="schedules-list">
      <div
        v-for="schedule in scheduledReports"
        :key="schedule.id"
        class="schedule-card"
      >
        <div class="schedule-header">
          <div class="schedule-title-row">
            <h4 class="schedule-name">{{ schedule.name }}</h4>
            <div class="schedule-status">
              <span
                class="status-badge"
                :class="schedule.enabled ? 'status-active' : 'status-inactive'"
              >
                {{ schedule.enabled ? 'Active' : 'Inactive' }}
              </span>
            </div>
          </div>
          <p class="schedule-meta">
            {{ formatFrequency(schedule) }} • {{ schedule.format.toUpperCase() }} • 
            {{ schedule.deliveryMethod }}
          </p>
        </div>

        <div class="schedule-info">
          <div class="info-item">
            <span class="info-label">Next Run:</span>
            <span class="info-value">{{ formatDate(schedule.nextRun) }}</span>
          </div>
          <div class="info-item" v-if="schedule.lastRun">
            <span class="info-label">Last Run:</span>
            <span class="info-value">{{ formatDate(schedule.lastRun) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Runs:</span>
            <span class="info-value">{{ schedule.runCount || 0 }}</span>
          </div>
          <div class="info-item" v-if="schedule.lastError">
            <span class="info-label error">Last Error:</span>
            <span class="info-value error">{{ schedule.lastError }}</span>
          </div>
        </div>

        <div class="schedule-actions">
          <button
            @click="toggleSchedule(schedule.id, !schedule.enabled)"
            class="action-btn"
            :class="schedule.enabled ? 'disable-btn' : 'enable-btn'"
          >
            <Power v-if="schedule.enabled" class="action-icon" />
            <PowerOff v-else class="action-icon" />
            {{ schedule.enabled ? 'Disable' : 'Enable' }}
          </button>
          <button @click="runNow(schedule.id)" class="action-btn run-btn">
            <Play class="action-icon" />
            Run Now
          </button>
          <button @click="editSchedule(schedule)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click="deleteSchedule(schedule.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <!-- Create/Edit Schedule Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showCreateModal || editingSchedule" class="modal-overlay" @click="closeModal">
          <div class="modal-content schedule-modal" @click.stop>
            <div class="modal-header">
              <div class="modal-title-group">
                <Clock class="modal-title-icon" />
                <h2>{{ editingSchedule ? 'Edit Schedule' : 'Create Scheduled Report' }}</h2>
              </div>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <div class="modal-body">
              <form @submit.prevent="saveSchedule">
                <div class="form-group">
                  <label>Schedule Name</label>
                  <input
                    v-model="scheduleForm.name"
                    type="text"
                    class="form-input"
                    placeholder="Enter schedule name"
                    required
                  />
                </div>

                <div class="form-group">
                  <label>Frequency</label>
                  <select v-model="scheduleForm.frequency" class="form-input" @change="updateNextRunPreview">
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>

                <div v-if="scheduleForm.frequency === 'weekly'" class="form-group">
                  <label>Day of Week</label>
                  <select v-model="scheduleForm.dayOfWeek" class="form-input" @change="updateNextRunPreview">
                    <option :value="0">Sunday</option>
                    <option :value="1">Monday</option>
                    <option :value="2">Tuesday</option>
                    <option :value="3">Wednesday</option>
                    <option :value="4">Thursday</option>
                    <option :value="5">Friday</option>
                    <option :value="6">Saturday</option>
                  </select>
                </div>

                <div v-if="scheduleForm.frequency === 'monthly'" class="form-group">
                  <label>Day of Month</label>
                  <input
                    v-model.number="scheduleForm.dayOfMonth"
                    type="number"
                    min="1"
                    max="31"
                    class="form-input"
                    @change="updateNextRunPreview"
                  />
                </div>

                <div class="form-group">
                  <label>Time</label>
                  <input
                    v-model="scheduleForm.time"
                    type="time"
                    class="form-input"
                    @change="updateNextRunPreview"
                  />
                </div>

                <div class="form-group">
                  <label>Report Format</label>
                  <select v-model="scheduleForm.format" class="form-input">
                    <option value="html">HTML</option>
                    <option value="json">JSON</option>
                    <option value="xml">XML</option>
                    <option value="pdf">PDF</option>
                    <option value="excel">Excel</option>
                  </select>
                </div>

                <div class="form-group">
                  <label>Delivery Method</label>
                  <select v-model="scheduleForm.deliveryMethod" class="form-input">
                    <option value="storage">Store in Reports</option>
                    <option value="email">Email</option>
                    <option value="webhook">Webhook</option>
                  </select>
                </div>

                <div v-if="scheduleForm.deliveryMethod === 'email'" class="form-group">
                  <label>Recipients (comma-separated)</label>
                  <input
                    v-model="scheduleForm.recipients"
                    type="text"
                    class="form-input"
                    placeholder="email1@example.com, email2@example.com"
                  />
                </div>

                <div v-if="scheduleForm.deliveryMethod === 'webhook'" class="form-group">
                  <label>Webhook URL</label>
                  <input
                    v-model="scheduleForm.webhookUrl"
                    type="url"
                    class="form-input"
                    placeholder="https://example.com/webhook"
                  />
                </div>

                <div class="form-group">
                  <label class="checkbox-option">
                    <input
                      v-model="scheduleForm.enabled"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Enable schedule</span>
                  </label>
                </div>

                <div v-if="nextRunPreview" class="preview-box">
                  <strong>Next Run:</strong> {{ formatDate(nextRunPreview) }}
                </div>

                <div class="modal-actions">
                  <button type="button" @click="closeModal" class="btn-secondary">
                    Cancel
                  </button>
                  <button type="submit" class="btn-primary" :disabled="saving">
                    <Loader2 v-if="saving" class="btn-icon spinning" />
                    <Clock v-else class="btn-icon" />
                    {{ saving ? 'Saving...' : (editingSchedule ? 'Update' : 'Create') }}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { Teleport } from 'vue';
import {
  Clock,
  Power,
  PowerOff,
  Play,
  Edit,
  Trash2,
  X,
  Loader2,
} from 'lucide-vue-next';
import axios from 'axios';

interface ScheduledReport {
  id: string;
  name: string;
  enabled: boolean;
  frequency: 'daily' | 'weekly' | 'monthly' | 'custom';
  time?: string;
  dayOfWeek?: number;
  dayOfMonth?: number;
  format: string;
  deliveryMethod: 'email' | 'webhook' | 'storage';
  recipients?: string[];
  webhookUrl?: string;
  nextRun: Date | string;
  lastRun?: Date | string;
  runCount: number;
  lastError?: string;
}

const loading = ref(false);
const saving = ref(false);
const scheduledReports = ref<ScheduledReport[]>([]);
const showCreateModal = ref(false);
const editingSchedule = ref<ScheduledReport | null>(null);
const nextRunPreview = ref<Date | null>(null);

const scheduleForm = ref({
  name: '',
  enabled: true,
  frequency: 'weekly' as 'daily' | 'weekly' | 'monthly',
  time: '09:00',
  dayOfWeek: 1,
  dayOfMonth: 1,
  format: 'html' as 'json' | 'html' | 'xml' | 'pdf' | 'excel',
  deliveryMethod: 'storage' as 'email' | 'webhook' | 'storage',
  recipients: '',
  webhookUrl: '',
});

const loadScheduledReports = async () => {
  loading.value = true;
  try {
    const response = await axios.get('/api/scheduled-reports');
    scheduledReports.value = response.data.map((r: any) => ({
      ...r,
      nextRun: new Date(r.nextRun),
      lastRun: r.lastRun ? new Date(r.lastRun) : undefined,
    }));
  } catch (error) {
    console.error('Failed to load scheduled reports:', error);
  } finally {
    loading.value = false;
  }
};

const formatFrequency = (schedule: ScheduledReport): string => {
  if (schedule.frequency === 'daily') {
    return `Daily at ${schedule.time || '00:00'}`;
  } else if (schedule.frequency === 'weekly') {
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    return `Weekly on ${days[schedule.dayOfWeek || 1]} at ${schedule.time || '00:00'}`;
  } else if (schedule.frequency === 'monthly') {
    return `Monthly on day ${schedule.dayOfMonth || 1} at ${schedule.time || '00:00'}`;
  }
  return schedule.frequency;
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const updateNextRunPreview = () => {
  // Calculate next run based on form values
  const now = new Date();
  const next = new Date(now);

  if (scheduleForm.value.frequency === 'daily') {
    if (scheduleForm.value.time) {
      const [hours, minutes] = scheduleForm.value.time.split(':').map(Number);
      next.setHours(hours, minutes, 0, 0);
      if (next <= now) {
        next.setDate(next.getDate() + 1);
      }
    } else {
      next.setDate(next.getDate() + 1);
    }
  } else if (scheduleForm.value.frequency === 'weekly') {
    const dayOfWeek = scheduleForm.value.dayOfWeek ?? 1;
    const currentDay = now.getDay();
    let daysUntilNext = (dayOfWeek - currentDay + 7) % 7;
    if (daysUntilNext === 0) daysUntilNext = 7;
    next.setDate(next.getDate() + daysUntilNext);
    if (scheduleForm.value.time) {
      const [hours, minutes] = scheduleForm.value.time.split(':').map(Number);
      next.setHours(hours, minutes, 0, 0);
    }
  } else if (scheduleForm.value.frequency === 'monthly') {
    next.setMonth(next.getMonth() + 1);
    next.setDate(scheduleForm.value.dayOfMonth || 1);
    if (scheduleForm.value.time) {
      const [hours, minutes] = scheduleForm.value.time.split(':').map(Number);
      next.setHours(hours, minutes, 0, 0);
    }
  }

  nextRunPreview.value = next;
};

const saveSchedule = async () => {
  saving.value = true;
  try {
    const data = {
      name: scheduleForm.value.name,
      enabled: scheduleForm.value.enabled,
      frequency: scheduleForm.value.frequency,
      time: scheduleForm.value.time,
      dayOfWeek: scheduleForm.value.frequency === 'weekly' ? scheduleForm.value.dayOfWeek : undefined,
      dayOfMonth: scheduleForm.value.frequency === 'monthly' ? scheduleForm.value.dayOfMonth : undefined,
      format: scheduleForm.value.format,
      deliveryMethod: scheduleForm.value.deliveryMethod,
      recipients: scheduleForm.value.deliveryMethod === 'email' && scheduleForm.value.recipients
        ? scheduleForm.value.recipients.split(',').map(e => e.trim())
        : undefined,
      webhookUrl: scheduleForm.value.deliveryMethod === 'webhook' ? scheduleForm.value.webhookUrl : undefined,
    };

    if (editingSchedule.value) {
      await axios.put(`/api/scheduled-reports/${editingSchedule.value.id}`, data);
    } else {
      await axios.post('/api/scheduled-reports', data);
    }

    await loadScheduledReports();
    closeModal();
  } catch (error: any) {
    console.error('Failed to save schedule:', error);
    alert(error.response?.data?.message || 'Failed to save schedule. Please try again.');
  } finally {
    saving.value = false;
  }
};

const toggleSchedule = async (id: string, enabled: boolean) => {
  try {
    await axios.patch(`/api/scheduled-reports/${id}/toggle`, { enabled });
    await loadScheduledReports();
  } catch (error: any) {
    console.error('Failed to toggle schedule:', error);
    alert('Failed to toggle schedule. Please try again.');
  }
};

const runNow = async (id: string) => {
  try {
    await axios.post(`/api/scheduled-reports/${id}/run-now`);
    alert('Report execution started!');
    await loadScheduledReports();
  } catch (error: any) {
    console.error('Failed to run schedule:', error);
    alert(error.response?.data?.message || 'Failed to run schedule. Please try again.');
  }
};

const editSchedule = (schedule: ScheduledReport) => {
  editingSchedule.value = schedule;
  scheduleForm.value = {
    name: schedule.name,
    enabled: schedule.enabled,
    frequency: schedule.frequency,
    time: schedule.time || '09:00',
    dayOfWeek: schedule.dayOfWeek || 1,
    dayOfMonth: schedule.dayOfMonth || 1,
    format: schedule.format as any,
    deliveryMethod: schedule.deliveryMethod,
    recipients: schedule.recipients?.join(', ') || '',
    webhookUrl: schedule.webhookUrl || '',
  };
  updateNextRunPreview();
};

const deleteSchedule = async (id: string) => {
  if (!confirm('Are you sure you want to delete this scheduled report?')) {
    return;
  }

  try {
    await axios.delete(`/api/scheduled-reports/${id}`);
    await loadScheduledReports();
  } catch (error: any) {
    console.error('Failed to delete schedule:', error);
    alert('Failed to delete schedule. Please try again.');
  }
};

const closeModal = () => {
  showCreateModal.value = false;
  editingSchedule.value = null;
  scheduleForm.value = {
    name: '',
    enabled: true,
    frequency: 'weekly',
    time: '09:00',
    dayOfWeek: 1,
    dayOfMonth: 1,
    format: 'html',
    deliveryMethod: 'storage',
    recipients: '',
    webhookUrl: '',
  };
  nextRunPreview.value = null;
};

onMounted(() => {
  loadScheduledReports();
});
</script>

<style scoped>
.scheduled-reports {
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
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.btn-primary-small {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 16px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  font-size: 0.875rem;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-primary-small:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.loading-state,
.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.empty-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.schedules-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.schedule-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  transition: all 0.3s;
}

.schedule-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

.schedule-header {
  margin-bottom: 16px;
}

.schedule-title-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 8px;
}

.schedule-name {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-inactive {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.schedule-meta {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.schedule-info {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 12px;
  margin-bottom: 16px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.75rem;
  color: #718096;
}

.info-label.error {
  color: #fc8181;
}

.info-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
}

.info-value.error {
  color: #fc8181;
}

.schedule-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
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

.enable-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.disable-btn:hover {
  background: rgba(251, 191, 36, 0.1);
  border-color: rgba(251, 191, 36, 0.5);
  color: #fbbf24;
}

.run-btn:hover {
  background: rgba(34, 197, 94, 0.1);
  border-color: rgba(34, 197, 94, 0.5);
  color: #22c55e;
}

.edit-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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

.schedule-modal {
  max-width: 600px;
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
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #ffffff;
  font-size: 0.9rem;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.preview-box {
  padding: 12px;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  font-size: 0.875rem;
  margin-bottom: 20px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
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

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
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

