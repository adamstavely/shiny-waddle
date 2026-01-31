<template>
  <div class="policy-approvals">
    <div class="approvals-header">
      <h3>Approval Workflow</h3>
      <button
        v-if="!hasPendingApproval"
        @click="showCreateModal = true"
        class="btn-primary"
      >
        <CheckCircle class="icon" />
        Request Approval
      </button>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading approvals...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
    </div>

    <div v-else-if="approvals.length === 0" class="empty-state">
      <p>No approval requests. Request approval to proceed with policy changes.</p>
    </div>

    <div v-else class="approvals-list">
      <div
        v-for="approval in approvals"
        :key="approval.id"
        class="approval-card"
        :class="`status-${approval.status}`"
      >
        <div class="approval-header">
          <div>
            <h4>Approval Request #{{ approval.id.slice(-8) }}</h4>
            <span class="approval-status-badge" :class="`status-${approval.status}`">
              {{ approval.status.toUpperCase() }}
            </span>
          </div>
          <div class="approval-meta">
            <span>Requested by: {{ approval.requestedBy }}</span>
            <span>{{ formatDate(approval.requestedAt) }}</span>
          </div>
        </div>

        <div v-if="approval.rejectionReason" class="rejection-reason">
          <AlertCircle class="icon" />
          <strong>Rejected:</strong> {{ approval.rejectionReason }}
        </div>

        <div class="approval-stages">
          <div
            v-for="(stage, index) in approval.stages"
            :key="index"
            class="stage-card"
            :class="{
              'stage-current': index + 1 === approval.currentStage,
              'stage-complete': stage.status === 'approved',
              'stage-rejected': stage.status === 'rejected',
            }"
          >
            <div class="stage-header">
              <h5>Stage {{ stage.stageNumber }}</h5>
              <span class="stage-status" :class="`status-${stage.status}`">
                {{ stage.status }}
              </span>
            </div>

            <div class="stage-details">
              <p>
                <strong>Required:</strong> {{ stage.requiredApprovals }} approval(s)
              </p>
              <p>
                <strong>Approvers:</strong> {{ stage.approvers.join(', ') }}
              </p>

              <div v-if="stage.approvals.length > 0" class="approvals-list">
                <div
                  v-for="approval in stage.approvals"
                  :key="approval.approverId"
                  class="approval-item"
                >
                  <CheckCircle class="icon approved" />
                  <span>{{ approval.approverId }}</span>
                  <span class="approval-date">{{ formatDate(approval.approvedAt) }}</span>
                </div>
              </div>

              <div v-if="stage.rejections.length > 0" class="rejections-list">
                <div
                  v-for="rejection in stage.rejections"
                  :key="rejection.approverId"
                  class="rejection-item"
                >
                  <XCircle class="icon rejected" />
                  <span>{{ rejection.approverId }}</span>
                  <span class="rejection-reason">{{ rejection.reason }}</span>
                </div>
              </div>
            </div>

            <div
              v-if="
                index + 1 === approval.currentStage &&
                approval.status === 'pending' &&
                canApprove(stage)
              "
              class="stage-actions"
            >
              <button @click="showApproveModal(approval, stage)" class="btn-approve">
                <CheckCircle class="icon" />
                Approve
              </button>
              <button @click="showRejectModal(approval, stage)" class="btn-reject">
                <XCircle class="icon" />
                Reject
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Approval Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click="showCreateModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>Create Approval Request</h3>
          <button @click="showCreateModal = false" class="btn-close">
            <X class="icon" />
          </button>
        </div>

        <form @submit.prevent="createApproval" class="modal-body">
          <div class="form-group">
            <label>Requested By</label>
            <input v-model="approvalForm.requestedBy" type="text" required />
          </div>

          <div class="form-group">
            <label>Approval Stages</label>
            <div
              v-for="(stage, index) in approvalForm.stages"
              :key="index"
              class="stage-form"
            >
              <h4>Stage {{ index + 1 }}</h4>
              <div class="form-row">
                <div class="form-group">
                  <label>Approvers (comma-separated)</label>
                  <input
                    v-model="approvalForm.stages[index].approversInput"
                    type="text"
                    placeholder="user1, user2, user3"
                    required
                  />
                </div>
                <div class="form-group">
                  <label>Required Approvals</label>
                  <input
                    v-model.number="approvalForm.stages[index].requiredApprovals"
                    type="number"
                    min="1"
                    required
                  />
                </div>
              </div>
              <button
                v-if="approvalForm.stages.length > 1"
                @click="removeStage(index)"
                type="button"
                class="btn-remove-stage"
              >
                Remove Stage
              </button>
            </div>
            <button @click="addStage" type="button" class="btn-add-stage">
              Add Stage
            </button>
          </div>

          <div class="modal-footer">
            <button type="button" @click="showCreateModal = false" class="btn-cancel">
              Cancel
            </button>
            <button type="submit" :disabled="submitting" class="btn-submit">
              {{ submitting ? 'Creating...' : 'Create Approval Request' }}
            </button>
          </div>
        </form>
      </div>
    </div>

    <!-- Approve/Reject Modal -->
    <div v-if="showActionModal" class="modal-overlay" @click="showActionModal = false">
      <div class="modal-content" @click.stop>
        <div class="modal-header">
          <h3>{{ actionModalType === 'approve' ? 'Approve' : 'Reject' }} Policy</h3>
          <button @click="showActionModal = false" class="btn-close">
            <X class="icon" />
          </button>
        </div>

        <form @submit.prevent="submitAction" class="modal-body">
          <div class="form-group">
            <label>Your User ID</label>
            <input v-model="actionForm.approverId" type="text" required />
          </div>

          <div v-if="actionModalType === 'approve'" class="form-group">
            <label>Comments (optional)</label>
            <textarea v-model="actionForm.comments" rows="3"></textarea>
          </div>

          <div v-if="actionModalType === 'reject'" class="form-group">
            <label>Rejection Reason</label>
            <textarea v-model="actionForm.reason" rows="3" required></textarea>
          </div>

          <div class="modal-footer">
            <button type="button" @click="showActionModal = false" class="btn-cancel">
              Cancel
            </button>
            <button type="submit" :disabled="submitting" class="btn-submit">
              {{ submitting ? 'Processing...' : actionModalType === 'approve' ? 'Approve' : 'Reject' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { CheckCircle, XCircle, AlertTriangle, X } from 'lucide-vue-next';
import axios from 'axios';

interface ApprovalStage {
  stageNumber: number;
  approvers: string[];
  requiredApprovals: number;
  approvals: Array<{
    approverId: string;
    approvedAt: Date | string;
    comments?: string;
  }>;
  rejections: Array<{
    approverId: string;
    rejectedAt: Date | string;
    reason: string;
  }>;
  status: 'pending' | 'approved' | 'rejected';
}

interface PolicyApproval {
  id: string;
  policyId: string;
  requestedBy: string;
  requestedAt: Date | string;
  stages: ApprovalStage[];
  status: 'pending' | 'approved' | 'rejected' | 'cancelled';
  currentStage: number;
  approvedAt?: Date | string;
  rejectedAt?: Date | string;
  rejectedBy?: string;
  rejectionReason?: string;
}

const props = defineProps<{
  policyId: string;
  currentUserId?: string;
}>();

const approvals = ref<PolicyApproval[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showCreateModal = ref(false);
const showActionModal = ref(false);
const actionModalType = ref<'approve' | 'reject'>('approve');
const submitting = ref(false);
const currentApproval = ref<PolicyApproval | null>(null);
const currentStage = ref<ApprovalStage | null>(null);

const approvalForm = ref({
  requestedBy: '',
  stages: [
    {
      approversInput: '',
      requiredApprovals: 1,
    },
  ],
});

const actionForm = ref({
  approverId: props.currentUserId || '',
  comments: '',
  reason: '',
});

const hasPendingApproval = computed(() => {
  return approvals.value.some(a => a.status === 'pending');
});

const loadApprovals = async () => {
  loading.value = true;
  error.value = null;

  try {
    const response = await axios.get(`/api/policies/${props.policyId}/approvals`);
    approvals.value = response.data.map((a: PolicyApproval) => ({
      ...a,
      requestedAt: new Date(a.requestedAt),
      approvedAt: a.approvedAt ? new Date(a.approvedAt) : undefined,
      rejectedAt: a.rejectedAt ? new Date(a.rejectedAt) : undefined,
      stages: a.stages.map(s => ({
        ...s,
        approvals: s.approvals.map(app => ({
          ...app,
          approvedAt: new Date(app.approvedAt),
        })),
        rejections: s.rejections.map(rej => ({
          ...rej,
          rejectedAt: new Date(rej.rejectedAt),
        })),
      })),
    }));
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load approvals';
    console.error('Error loading approvals:', err);
  } finally {
    loading.value = false;
  }
};

const createApproval = async () => {
  submitting.value = true;
  try {
    const stages = approvalForm.value.stages.map(s => ({
      approvers: s.approversInput.split(',').map(a => a.trim()).filter(Boolean),
      requiredApprovals: s.requiredApprovals,
    }));

    await axios.post(`/api/policies/${props.policyId}/approvals`, {
      requestedBy: approvalForm.value.requestedBy,
      stages,
    });

    await loadApprovals();
    showCreateModal.value = false;
    approvalForm.value = {
      requestedBy: '',
      stages: [{ approversInput: '', requiredApprovals: 1 }],
    };
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to create approval';
    console.error('Error creating approval:', err);
  } finally {
    submitting.value = false;
  }
};

const addStage = () => {
  approvalForm.value.stages.push({
    approversInput: '',
    requiredApprovals: 1,
  });
};

const removeStage = (index: number) => {
  approvalForm.value.stages.splice(index, 1);
};

const showApproveModal = (approval: PolicyApproval, stage: ApprovalStage) => {
  currentApproval.value = approval;
  currentStage.value = stage;
  actionModalType.value = 'approve';
  actionForm.value = {
    approverId: props.currentUserId || '',
    comments: '',
    reason: '',
  };
  showActionModal.value = true;
};

const showRejectModal = (approval: PolicyApproval, stage: ApprovalStage) => {
  currentApproval.value = approval;
  currentStage.value = stage;
  actionModalType.value = 'reject';
  actionForm.value = {
    approverId: props.currentUserId || '',
    comments: '',
    reason: '',
  };
  showActionModal.value = true;
};

const submitAction = async () => {
  if (!currentApproval.value) return;

  submitting.value = true;
  try {
    if (actionModalType.value === 'approve') {
      await axios.post(`/api/policies/approvals/${currentApproval.value.id}/approve`, {
        approverId: actionForm.value.approverId,
        comments: actionForm.value.comments,
      });
    } else {
      await axios.post(`/api/policies/approvals/${currentApproval.value.id}/reject`, {
        approverId: actionForm.value.approverId,
        reason: actionForm.value.reason,
      });
    }

    await loadApprovals();
    showActionModal.value = false;
    currentApproval.value = null;
    currentStage.value = null;
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || `Failed to ${actionModalType.value}`;
    console.error(`Error ${actionModalType.value}ing:`, err);
  } finally {
    submitting.value = false;
  }
};

const canApprove = (stage: ApprovalStage): boolean => {
  // In production, check if current user is in approvers list
  return true; // Simplified for now
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
  loadApprovals();
});
</script>

<style scoped>
.policy-approvals {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.approvals-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.approvals-header h3 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.btn-primary {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--gradient-primary);
  border: none;
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.approvals-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.approval-card {
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  border-left: 4px solid var(--color-primary);
}

.approval-card.status-approved {
  border-left-color: var(--color-success);
}

.approval-card.status-rejected {
  border-left-color: var(--color-error);
}

.approval-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-md);
}

.approval-header h4 {
  margin: 0 0 var(--spacing-xs) 0;
}

.approval-status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  margin-left: var(--spacing-sm);
}

.approval-status-badge.status-pending {
  background: var(--color-warning);
  color: white;
}

.approval-status-badge.status-approved {
  background: var(--color-success);
  color: white;
}

.approval-status-badge.status-rejected {
  background: var(--color-error);
  color: white;
}

.approval-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: var(--spacing-xs);
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.rejection-reason {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: rgba(var(--color-error-rgb), 0.1);
  border-left: 3px solid var(--color-error);
  border-radius: var(--border-radius-sm);
  margin-bottom: var(--spacing-md);
  color: var(--color-error);
}

.approval-stages {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.stage-card {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.stage-card.stage-current {
  border-color: var(--color-primary);
  border-width: 2px;
}

.stage-card.stage-complete {
  border-color: var(--color-success);
}

.stage-card.stage-rejected {
  border-color: var(--color-error);
}

.stage-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.stage-header h5 {
  margin: 0;
}

.stage-status {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.stage-status.status-pending {
  background: rgba(var(--color-warning-rgb), 0.1);
  color: var(--color-warning);
}

.stage-status.status-approved {
  background: rgba(var(--color-success-rgb), 0.1);
  color: var(--color-success);
}

.stage-status.status-rejected {
  background: rgba(var(--color-error-rgb), 0.1);
  color: var(--color-error);
}

.stage-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.approvals-list,
.rejections-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
  margin-top: var(--spacing-sm);
}

.approval-item,
.rejection-item {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-xs);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-sm);
}

.icon {
  width: 18px;
  height: 18px;
}

.icon.approved {
  color: var(--color-success);
}

.icon.rejected {
  color: var(--color-error);
}

.approval-date,
.rejection-reason {
  margin-left: auto;
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.stage-actions {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.btn-approve,
.btn-reject {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  border: none;
  border-radius: var(--border-radius-md);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
}

.btn-approve {
  background: var(--color-success);
  color: white;
}

.btn-reject {
  background: var(--color-error);
  color: white;
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
  max-width: 700px;
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
.form-group textarea {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-family: inherit;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.stage-form {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-md);
}

.stage-form h4 {
  margin: 0 0 var(--spacing-md) 0;
}

.btn-add-stage,
.btn-remove-stage {
  padding: var(--spacing-xs) var(--spacing-sm);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-sm);
  background: var(--color-bg-overlay-light);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
}

.btn-remove-stage {
  background: rgba(var(--color-error-rgb), 0.1);
  color: var(--color-error);
  border-color: var(--color-error);
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
.btn-submit {
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

.btn-submit {
  background: var(--gradient-primary);
  color: var(--color-text-primary);
}

.btn-submit:disabled {
  opacity: 0.5;
  cursor: not-allowed;
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
</style>
