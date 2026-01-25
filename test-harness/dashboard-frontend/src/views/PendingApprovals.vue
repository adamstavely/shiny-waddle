<template>
  <div class="pending-approvals-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Pending Approvals</h1>
          <p class="page-description">Review and approve risk acceptance and false positive requests</p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading pending approvals...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="!pendingApprovals || pendingApprovals.length === 0" class="empty-state">
      <ShieldCheck class="empty-icon" />
      <p>No pending approvals</p>
    </div>
    <div v-else class="approvals-list">
      <div
        v-for="approval in (pendingApprovals || [])"
        :key="approval.id"
        class="approval-card"
      >
        <div class="approval-header">
          <div class="approval-title-group">
            <h3>{{ approval.metadata?.findingTitle || 'Unknown Finding' }}</h3>
            <span :class="`type-badge type-${approval.type}`">
              {{ approval.type === 'risk-acceptance' ? 'Risk Acceptance' : 'False Positive' }}
            </span>
          </div>
          <div class="approval-meta">
            <span class="severity-badge" :class="`severity-${approval.metadata?.findingSeverity}`">
              {{ approval.metadata?.findingSeverity }}
            </span>
            <span class="request-date">Requested {{ formatDate(approval.requestedAt) }}</span>
          </div>
        </div>

        <div class="approval-body">
          <div class="approval-reason">
            <strong>Reason:</strong>
            <p>{{ approval.reason }}</p>
          </div>

          <div class="approval-required">
            <strong>Required Approvers:</strong>
            <div class="approvers-list">
              <span
                v-for="role in approval.requiredApprovers"
                :key="role"
                class="approver-role-badge"
              >
                {{ formatRole(role) }}
              </span>
            </div>
          </div>

          <div class="approval-status">
            <strong>Current Status:</strong>
            <div class="approvers-status">
              <div
                v-for="(app, index) in approval.approvals"
                :key="index"
                class="approver-status-item"
              >
                <span class="approver-name">{{ formatRole(app.approverRole) }}</span>
                <span :class="`status-badge status-${app.status}`">
                  {{ app.status }}
                </span>
              </div>
            </div>
          </div>
        </div>

        <div class="approval-footer">
          <button @click="viewFinding(approval.findingId)" class="btn-link">
            View Finding
          </button>
          <div class="approval-actions">
            <button @click="rejectApproval(approval)" class="btn-reject">
              Reject
            </button>
            <button @click="approveRequest(approval)" class="btn-approve">
              Approve
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Approval Modal -->
    <ApprovalActionModal
      v-if="selectedApproval"
      :isOpen="modals.isOpen('approval')"
      :approval="selectedApproval"
      :action="approvalAction"
      @update:isOpen="modals.close('approval')"
      @submitted="loadPendingApprovals"
    />

    <!-- Finding Detail Modal -->
    <FindingDetailModal
      v-if="findingModal.data.value"
      :isOpen="findingModal.isOpen.value"
      :finding="findingModal.data.value"
      @update:isOpen="findingModal.close()"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { ShieldCheck } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import ApprovalActionModal from '../components/ApprovalActionModal.vue';
import FindingDetailModal from '../components/FindingDetailModal.vue';
import { useAuth } from '../composables/useAuth';
import { useApiDataAuto } from '../composables/useApiData';
import { useModal, useMultiModal } from '../composables/useModal';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Pending Approvals', to: '/pending-approvals' },
];

// Get current user from auth context
const { user, approverRole } = useAuth();

// Use composable for API data fetching
const { data: pendingApprovals, loading, error, reload: loadPendingApprovals } = useApiDataAuto(
  async () => {
    if (!approverRole.value) {
      throw new Error('You do not have permission to view approvals. You must be a Cyber Risk Manager or Data Steward.');
    }

    const response = await axios.get('/api/finding-approvals/pending', {
      params: {
        approverRole: approverRole.value,
      },
    });
    return response.data.map((a: any) => ({
      ...a,
      requestedAt: new Date(a.requestedAt),
      approvals: a.approvals.map((app: any) => ({
        ...app,
        approvedAt: app.approvedAt ? new Date(app.approvedAt) : undefined,
      })),
    }));
  },
  {
    initialData: [],
    errorMessage: 'Failed to load pending approvals',
  }
);

// Use composable for modal state management
const modals = useMultiModal(['approval', 'finding']);
const selectedApproval = ref<any>(null);
const approvalAction = ref<'approve' | 'reject'>('approve');
const findingModal = useModal<any>();

const approveRequest = (approval: any) => {
  selectedApproval.value = approval;
  approvalAction.value = 'approve';
  modals.open('approval');
};

const rejectApproval = (approval: any) => {
  selectedApproval.value = approval;
  approvalAction.value = 'reject';
  modals.open('approval');
};

const viewFinding = async (findingId: string) => {
  try {
    const response = await axios.get(`/api/unified-findings/${findingId}`);
    const finding = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
    findingModal.open(finding);
  } catch (err) {
    console.error('Failed to load finding:', err);
  }
};

const formatDate = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};

const formatRole = (role: string) => {
  return role
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
};

onMounted(() => {
  loadPendingApprovals();
});
</script>

<style scoped>
.pending-approvals-page {
  padding: var(--spacing-lg);
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.page-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0;
}

.loading,
.error {
  padding: var(--spacing-lg);
  text-align: center;
  color: #ffffff;
}

.error {
  color: #fc8181;
}

.empty-state {
  text-align: center;
  padding: var(--spacing-2xl) var(--spacing-lg);
  color: var(--color-text-secondary);
}

.empty-icon {
  width: 64px;
  height: 64px;
  margin: 0 auto 16px;
  opacity: 0.5;
}

.approvals-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.approval-card {
  background: var(--color-bg-overlay-light);
  opacity: 0.6;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
}

.approval-header {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.approval-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.approval-title-group h3 {
  font-size: var(--font-size-xl);
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.type-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.type-badge.type-risk-acceptance {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.type-badge.type-false-positive {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.approval-meta {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.severity-badge.severity-critical {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.severity-badge.severity-high {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.request-date {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.approval-body {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.approval-reason strong,
.approval-required strong,
.approval-status strong {
  display: block;
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-sm);
}

.approval-reason p {
  color: #ffffff;
  margin: 0;
  line-height: 1.6;
}

.approvers-list {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
}

.approver-role-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--border-color-muted);
  color: var(--color-primary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-sm);
  font-weight: 500;
}

.approvers-status {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.approver-status-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm) var(--spacing-sm);
  background: rgba(0, 0, 0, 0.3);
  border-radius: 6px;
}

.approver-name {
  font-size: var(--font-size-sm);
  color: #ffffff;
}

.status-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 500;
}

.status-badge.status-pending {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.status-badge.status-approved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.status-badge.status-rejected {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.approval-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-top: 16px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-link {
  background: transparent;
  border: none;
  color: #4facfe;
  cursor: pointer;
  text-decoration: underline;
  font-size: var(--font-size-sm);
}

.btn-link:hover {
  color: #00f2fe;
}

.approval-actions {
  display: flex;
  gap: var(--spacing-sm);
}

.btn-approve,
.btn-reject {
  padding: var(--spacing-sm) var(--spacing-lg);
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: all 0.2s;
}

.btn-approve {
  background: linear-gradient(135deg, var(--color-success) 0%, #16a34a 100%);
  color: var(--color-text-primary);
}

.btn-approve:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(34, 197, 94, 0.4);
}

.btn-reject {
  background: transparent;
  border: var(--border-width-thin) solid var(--color-error);
  color: var(--color-error);
}

.btn-reject:hover {
  background: var(--color-error-bg);
}
</style>

