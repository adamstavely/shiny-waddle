<template>
  <div class="sla-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">SLA Management</h1>
          <p class="page-description">Configure service level agreements and escalation workflows for violation remediation</p>
        </div>
        <button @click="showCreateModal = true" class="btn-primary">
          <Plus class="btn-icon" />
          Create SLA Policy
        </button>
      </div>
    </div>

    <!-- SLA Stats -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-value">{{ slaStats.total }}</div>
        <div class="stat-label">Total SLA Violations</div>
      </div>
      <div class="stat-card stat-on-track">
        <div class="stat-value">{{ slaStats.onTrack }}</div>
        <div class="stat-label">On Track</div>
      </div>
      <div class="stat-card stat-at-risk">
        <div class="stat-value">{{ slaStats.atRisk }}</div>
        <div class="stat-label">At Risk</div>
      </div>
      <div class="stat-card stat-breached">
        <div class="stat-value">{{ slaStats.breached }}</div>
        <div class="stat-label">Breached</div>
      </div>
      <div class="stat-card">
        <div class="stat-value">{{ Math.round(slaStats.averageResolutionTime) }}h</div>
        <div class="stat-label">Avg Resolution Time</div>
      </div>
    </div>

    <!-- SLA Policies -->
    <div class="section-header">
      <h2 class="section-title">SLA Policies</h2>
      <p class="section-description">Define resolution targets and escalation rules by severity</p>
    </div>

    <div class="policies-grid">
      <div
        v-for="policy in policies"
        :key="policy.id"
        class="policy-card"
        :class="`policy-${policy.severity}`"
      >
        <div class="policy-card-header">
          <div class="policy-info">
            <div class="severity-badge" :class="`badge-${policy.severity}`">
              {{ policy.severity.toUpperCase() }}
            </div>
            <div>
              <h3 class="policy-name">{{ policy.name }}</h3>
              <p v-if="policy.description" class="policy-description">{{ policy.description }}</p>
            </div>
          </div>
          <div class="policy-status">
            <label class="toggle-label">
              <input
                type="checkbox"
                :checked="policy.enabled"
                @change="togglePolicy(policy.id)"
                class="toggle-input"
              />
              <span class="toggle-slider"></span>
              <span class="toggle-text">{{ policy.enabled ? 'Enabled' : 'Disabled' }}</span>
            </label>
          </div>
        </div>
        <div class="policy-card-content">
          <div class="policy-details">
            <div class="detail-item">
              <span class="detail-label">Target Resolution</span>
              <span class="detail-value">{{ policy.targetResolutionHours }} hours</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Warning Threshold</span>
              <span class="detail-value">{{ policy.warningThresholdHours }} hours</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Escalation Rules</span>
              <span class="detail-value">{{ policy.escalationRules.length }}</span>
            </div>
          </div>
          <div v-if="policy.escalationRules.length > 0" class="escalation-rules">
            <h4 class="rules-title">Escalation Rules</h4>
            <div
              v-for="rule in policy.escalationRules"
              :key="rule.id"
              class="escalation-rule"
            >
              <div class="rule-info">
                <span class="rule-trigger">After {{ rule.triggerHours }}h</span>
                <span class="rule-action">{{ rule.action }}</span>
                <span class="rule-target">{{ rule.target }}</span>
              </div>
            </div>
          </div>
        </div>
        <div class="policy-card-actions">
          <button @click="editPolicy(policy)" class="action-btn edit-btn">
            <Edit class="action-icon" />
            Edit
          </button>
          <button @click="deletePolicy(policy.id)" class="action-btn delete-btn">
            <Trash2 class="action-icon" />
            Delete
          </button>
        </div>
      </div>
    </div>

    <div v-if="policies.length === 0" class="empty-state">
      <Clock class="empty-icon" />
      <h3>No SLA Policies</h3>
      <p>Create SLA policies to track violation remediation timelines</p>
      <button @click="showCreateModal = true" class="btn-primary">
        <Plus class="btn-icon" />
        Create SLA Policy
      </button>
    </div>

    <!-- SLA Violations -->
    <div class="section-header" style="margin-top: 48px;">
      <h2 class="section-title">SLA Violations</h2>
      <p class="section-description">Track violations against SLA policies</p>
    </div>

    <div class="violations-table">
      <table>
        <thead>
          <tr>
            <th>Violation</th>
            <th>Policy</th>
            <th>Status</th>
            <th>Detected</th>
            <th>Target Resolution</th>
            <th>Time Remaining</th>
            <th>Assignee</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="slaViolation in slaViolations" :key="slaViolation.id">
            <td>
              <a :href="`/violations/${slaViolation.violationId}`" class="violation-link">
                {{ slaViolation.violationId.substring(0, 8) }}...
              </a>
            </td>
            <td>{{ getPolicyName(slaViolation.slaPolicyId) }}</td>
            <td>
              <span class="status-badge" :class="`status-${slaViolation.status}`">
                {{ formatStatus(slaViolation.status) }}
              </span>
            </td>
            <td>{{ formatDate(slaViolation.detectedAt) }}</td>
            <td>{{ formatDate(slaViolation.targetResolutionAt) }}</td>
            <td>
              <span :class="getTimeRemainingClass(slaViolation)">
                {{ getTimeRemaining(slaViolation) }}
              </span>
            </td>
            <td>{{ slaViolation.currentAssignee || '-' }}</td>
            <td>
              <button
                v-if="!slaViolation.resolvedAt"
                @click="resolveSLAViolation(slaViolation.id)"
                class="action-btn-small resolve-btn"
              >
                Resolve
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create/Edit Policy Modal -->
    <Teleport to="body">
      <Transition name="modal">
        <div v-if="showCreateModal || editingPolicy" class="modal-overlay" @click="closeModal">
          <div class="modal-content large" @click.stop>
            <div class="modal-header">
              <h2>{{ editingPolicy ? 'Edit SLA Policy' : 'Create SLA Policy' }}</h2>
              <button @click="closeModal" class="modal-close">
                <X class="close-icon" />
              </button>
            </div>
            <form @submit.prevent="savePolicy" class="modal-body">
              <div class="form-group">
                <label>Name</label>
                <input v-model="form.name" type="text" placeholder="Critical Violations SLA" required />
              </div>
              <div class="form-group">
                <label>Description</label>
                <textarea v-model="form.description" rows="3" placeholder="SLA policy for critical severity violations"></textarea>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>Severity</label>
                  <Dropdown
                    v-model="form.severity"
                    :options="severityOptions"
                    placeholder="Select severity"
                  />
                </div>
                <div class="form-group">
                  <label>Target Resolution (hours)</label>
                  <input v-model.number="form.targetResolutionHours" type="number" min="1" required />
                </div>
                <div class="form-group">
                  <label>Warning Threshold (hours)</label>
                  <input v-model.number="form.warningThresholdHours" type="number" min="1" required />
                </div>
              </div>

              <div class="escalation-rules-section">
                <div class="section-header-inline">
                  <h3>Escalation Rules</h3>
                  <button type="button" @click="addEscalationRule" class="btn-secondary btn-small">
                    <Plus class="btn-icon" />
                    Add Rule
                  </button>
                </div>
                <div
                  v-for="(rule, index) in form.escalationRules"
                  :key="index"
                  class="escalation-rule-form"
                >
                  <div class="form-row">
                    <div class="form-group">
                      <label>Trigger After (hours)</label>
                      <input v-model.number="rule.triggerHours" type="number" min="0" required />
                    </div>
                    <div class="form-group">
                      <label>Action</label>
                      <Dropdown
                        v-model="rule.action"
                        :options="actionOptions"
                        placeholder="Select action"
                      />
                    </div>
                    <div class="form-group">
                      <label>Target</label>
                      <input v-model="rule.target" type="text" placeholder="user@example.com or team-name" required />
                    </div>
                    <div class="form-group">
                      <button type="button" @click="removeEscalationRule(index)" class="btn-danger btn-small">
                        <X class="btn-icon" />
                      </button>
                    </div>
                  </div>
                  <div class="form-group">
                    <label>Message (optional)</label>
                    <input v-model="rule.message" type="text" placeholder="Escalation message" />
                  </div>
                </div>
                <div v-if="form.escalationRules.length === 0" class="empty-rules">
                  <p>No escalation rules. Add rules to automate violation handling.</p>
                </div>
              </div>

              <div class="form-group">
                <label class="checkbox-label">
                  <input v-model="form.enabled" type="checkbox" class="checkbox-input" />
                  <span>Enable policy</span>
                </label>
              </div>

              <div class="form-actions">
                <button type="button" @click="closeModal" class="btn-secondary">Cancel</button>
                <button type="submit" class="btn-primary" :disabled="saving">
                  {{ saving ? 'Saving...' : editingPolicy ? 'Update' : 'Create' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue';
import { Teleport, Transition } from 'vue';
import {
  Plus,
  X,
  Edit,
  Trash2,
  Clock,
  Settings,
} from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from '../components/Dropdown.vue';
import Breadcrumb from '../components/Breadcrumb.vue';
import type { SLAPolicy, SLAViolation, SLASeverity, SLAStatus, EscalationRule } from '../types/sla';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Admin', to: '/admin' },
  { label: 'SLA Management' },
];

const API_BASE_URL = '/api';

const policies = ref<SLAPolicy[]>([]);
const slaViolations = ref<SLAViolation[]>([]);
const slaStats = ref({
  total: 0,
  onTrack: 0,
  atRisk: 0,
  breached: 0,
  averageResolutionTime: 0,
});
const showCreateModal = ref(false);
const editingPolicy = ref<SLAPolicy | null>(null);
const saving = ref(false);

const form = ref({
  name: '',
  description: '',
  severity: 'critical' as SLASeverity,
  targetResolutionHours: 24,
  warningThresholdHours: 12,
  escalationRules: [] as Omit<EscalationRule, 'id'>[],
  enabled: true,
});

const severityOptions = [
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
];

const actionOptions = [
  { label: 'Notify', value: 'notify' },
  { label: 'Assign', value: 'assign' },
  { label: 'Escalate', value: 'escalate' },
  { label: 'Create Ticket', value: 'create-ticket' },
];

const loadPolicies = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/sla/policies`);
    policies.value = response.data;
  } catch (error) {
    console.error('Error loading policies:', error);
  }
};

const loadSLAViolations = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/sla/violations`);
    slaViolations.value = response.data;
  } catch (error) {
    console.error('Error loading SLA violations:', error);
  }
};

const loadSLAStats = async () => {
  try {
    const response = await axios.get(`${API_BASE_URL}/sla/stats`);
    slaStats.value = response.data;
  } catch (error) {
    console.error('Error loading SLA stats:', error);
  }
};

const savePolicy = async () => {
  saving.value = true;
  try {
    const payload = {
      ...form.value,
      escalationRules: form.value.escalationRules.map(rule => ({
        ...rule,
        id: undefined, // Will be generated by backend
      })),
    };

    if (editingPolicy.value) {
      await axios.patch(`${API_BASE_URL}/sla/policies/${editingPolicy.value.id}`, payload);
    } else {
      await axios.post(`${API_BASE_URL}/sla/policies`, payload);
    }

    await loadPolicies();
    closeModal();
  } catch (error: any) {
    alert(error.response?.data?.message || 'Failed to save policy');
  } finally {
    saving.value = false;
  }
};

const editPolicy = (policy: SLAPolicy) => {
  editingPolicy.value = policy;
  form.value = {
    name: policy.name,
    description: policy.description || '',
    severity: policy.severity,
    targetResolutionHours: policy.targetResolutionHours,
    warningThresholdHours: policy.warningThresholdHours,
    escalationRules: policy.escalationRules.map(rule => ({
      triggerHours: rule.triggerHours,
      action: rule.action,
      target: rule.target,
      notificationChannels: rule.notificationChannels,
      message: rule.message,
    })),
    enabled: policy.enabled,
  };
  showCreateModal.value = true;
};

const deletePolicy = async (id: string) => {
  if (!confirm('Are you sure you want to delete this SLA policy?')) {
    return;
  }

  try {
    await axios.delete(`${API_BASE_URL}/sla/policies/${id}`);
    await loadPolicies();
  } catch (error) {
    alert('Failed to delete policy');
  }
};

const togglePolicy = async (id: string) => {
  const policy = policies.value.find(p => p.id === id);
  if (!policy) return;

  try {
    await axios.patch(`${API_BASE_URL}/sla/policies/${id}`, {
      enabled: !policy.enabled,
    });
    await loadPolicies();
  } catch (error) {
    alert('Failed to update policy');
  }
};

const addEscalationRule = () => {
  form.value.escalationRules.push({
    triggerHours: 0,
    action: 'notify',
    target: '',
  });
};

const removeEscalationRule = (index: number) => {
  form.value.escalationRules.splice(index, 1);
};

const resolveSLAViolation = async (id: string) => {
  try {
    await axios.post(`${API_BASE_URL}/sla/violations/${id}/resolve`);
    await loadSLAViolations();
    await loadSLAStats();
  } catch (error) {
    alert('Failed to resolve SLA violation');
  }
};

const getPolicyName = (policyId: string): string => {
  const policy = policies.value.find(p => p.id === policyId);
  return policy?.name || 'Unknown';
};

const formatStatus = (status: SLAStatus): string => {
  const statusMap: Record<SLAStatus, string> = {
    on_track: 'On Track',
    at_risk: 'At Risk',
    breached: 'Breached',
  };
  return statusMap[status] || status;
};

const formatDate = (date: Date | string): string => {
  const d = new Date(date);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
};

const getTimeRemaining = (slaViolation: SLAViolation): string => {
  const now = new Date();
  const target = new Date(slaViolation.targetResolutionAt);
  const diff = target.getTime() - now.getTime();
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));

  if (diff < 0) {
    return `Overdue by ${Math.abs(hours)}h ${Math.abs(minutes)}m`;
  }
  return `${hours}h ${minutes}m`;
};

const getTimeRemainingClass = (slaViolation: SLAViolation): string => {
  if (slaViolation.status === 'breached') return 'time-overdue';
  if (slaViolation.status === 'at_risk') return 'time-warning';
  return 'time-ok';
};

const closeModal = () => {
  showCreateModal.value = false;
  editingPolicy.value = null;
  form.value = {
    name: '',
    description: '',
    severity: 'critical',
    targetResolutionHours: 24,
    warningThresholdHours: 12,
    escalationRules: [],
    enabled: true,
  };
};

onMounted(() => {
  loadPolicies();
  loadSLAViolations();
  loadSLAStats();
  
  // Refresh stats every minute
  setInterval(() => {
    loadSLAStats();
    loadSLAViolations();
  }, 60000);
});
</script>

<style scoped>
.sla-page {
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
  font-size: 2rem;
  font-weight: 700;
  margin: 0 0 8px 0;
  color: #fff;
}

.page-description {
  color: #a0aec0;
  margin: 0;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
}

.stat-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
  text-align: center;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #4facfe;
  margin-bottom: 8px;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

.stat-on-track .stat-value {
  color: #22c55e;
}

.stat-at-risk .stat-value {
  color: #fbbf24;
}

.stat-breached .stat-value {
  color: #fc8181;
}

.section-header {
  margin-bottom: 24px;
}

.section-header-inline {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.section-title {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0 0 8px 0;
  color: #fff;
}

.section-description {
  color: #a0aec0;
  margin: 0;
}

.policies-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 24px;
  margin-bottom: 48px;
}

.policy-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.policy-card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 20px;
}

.policy-info {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.severity-badge {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-critical {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.badge-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.badge-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.badge-low {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
}

.policy-name {
  font-size: 1.1rem;
  font-weight: 600;
  margin: 0 0 4px 0;
  color: #fff;
}

.policy-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
}

.policy-status {
  display: flex;
  align-items: center;
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.toggle-input {
  display: none;
}

.toggle-slider {
  width: 44px;
  height: 24px;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  position: relative;
  transition: background 0.2s;
}

.toggle-slider::before {
  content: '';
  position: absolute;
  width: 20px;
  height: 20px;
  background: #4facfe;
  border-radius: 50%;
  top: 2px;
  left: 2px;
  transition: transform 0.2s;
}

.toggle-input:checked + .toggle-slider {
  background: rgba(79, 172, 254, 0.4);
}

.toggle-input:checked + .toggle-slider::before {
  transform: translateX(20px);
}

.toggle-text {
  font-size: 0.875rem;
  color: #a0aec0;
}

.policy-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 16px;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
}

.detail-value {
  font-size: 0.875rem;
  color: #fff;
  font-weight: 500;
}

.escalation-rules {
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.rules-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  margin: 0 0 12px 0;
}

.escalation-rule {
  padding: 8px 12px;
  background: rgba(79, 172, 254, 0.05);
  border-radius: 6px;
  margin-bottom: 8px;
}

.rule-info {
  display: flex;
  gap: 12px;
  font-size: 0.875rem;
}

.rule-trigger {
  color: #4facfe;
  font-weight: 500;
}

.rule-action {
  color: #a0aec0;
}

.rule-target {
  color: #fff;
}

.policy-card-actions {
  display: flex;
  gap: 8px;
  padding-top: 20px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.action-btn {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 8px 16px;
  border-radius: 6px;
  border: none;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.edit-btn {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.edit-btn:hover {
  background: rgba(79, 172, 254, 0.2);
}

.delete-btn {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.delete-btn:hover {
  background: rgba(252, 129, 129, 0.2);
}

.action-icon {
  width: 16px;
  height: 16px;
}

.empty-state {
  text-align: center;
  padding: 64px 24px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px dashed rgba(79, 172, 254, 0.3);
  border-radius: 12px;
}

.empty-icon {
  width: 64px;
  height: 64px;
  color: #718096;
  margin: 0 auto 24px;
}

.empty-state h3 {
  font-size: 1.5rem;
  margin: 0 0 8px 0;
  color: #fff;
}

.empty-state p {
  color: #a0aec0;
  margin: 0 0 24px 0;
}

.violations-table {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  overflow: hidden;
}

.violations-table table {
  width: 100%;
  border-collapse: collapse;
}

.violations-table thead {
  background: rgba(79, 172, 254, 0.1);
}

.violations-table th {
  padding: 16px;
  text-align: left;
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.violations-table td {
  padding: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
  font-size: 0.875rem;
  color: #fff;
}

.violation-link {
  color: #4facfe;
  text-decoration: none;
}

.violation-link:hover {
  text-decoration: underline;
}

.status-badge {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
}

.status-on_track {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-at_risk {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.status-breached {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.time-ok {
  color: #22c55e;
}

.time-warning {
  color: #fbbf24;
}

.time-overdue {
  color: #fc8181;
  font-weight: 600;
}

.action-btn-small {
  padding: 6px 12px;
  border-radius: 6px;
  border: none;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.resolve-btn {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.resolve-btn:hover {
  background: rgba(34, 197, 94, 0.2);
}

/* Modal styles */
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
  padding: 24px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border-radius: 12px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 24px 48px rgba(0, 0, 0, 0.5);
}

.modal-content.large {
  max-width: 800px;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  margin: 0;
  color: #fff;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  color: #fff;
}

.close-icon {
  width: 24px;
  height: 24px;
}

.modal-body {
  padding: 24px;
}

.form-group {
  margin-bottom: 20px;
}

.form-row {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-group input,
.form-group textarea {
  width: 100%;
  padding: 10px 12px;
  background: rgba(15, 20, 25, 0.5);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 6px;
  color: #fff;
  font-size: 0.9rem;
  font-family: inherit;
}

.form-group input:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.escalation-rules-section {
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.escalation-rule-form {
  background: rgba(79, 172, 254, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 16px;
}

.empty-rules {
  padding: 24px;
  text-align: center;
  color: #718096;
  font-size: 0.875rem;
}

.btn-small {
  padding: 6px 12px;
  font-size: 0.875rem;
}

.btn-danger {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.btn-danger:hover {
  background: rgba(252, 129, 129, 0.2);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.btn-primary,
.btn-secondary {
  padding: 10px 20px;
  border-radius: 6px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  gap: 8px;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #fff;
  border: none;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.modal-enter-active,
.modal-leave-active {
  transition: opacity 0.3s;
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}
</style>

