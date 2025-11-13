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
    <div v-else-if="pendingApprovals.length === 0" class="empty-state">
      <ShieldCheck class="empty-icon" />
      <p>No pending approvals</p>
    </div>
    <div v-else class="approvals-list">
      <div
        v-for="approval in pendingApprovals"
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
      :isOpen="showApprovalModal"
      :approval="selectedApproval"
      :action="approvalAction"
      @update:isOpen="showApprovalModal = false"
      @submitted="loadPendingApprovals"
    />

    <!-- Finding Detail Modal -->
    <FindingDetailModal
      v-if="selectedFinding"
      :isOpen="showFindingModal"
      :finding="selectedFinding"
      @update:isOpen="showFindingModal = false"
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

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Pending Approvals', to: '/pending-approvals' },
];

const loading = ref(true);
const error = ref<string | null>(null);
const pendingApprovals = ref<any[]>([]);
const selectedApproval = ref<any>(null);
const showApprovalModal = ref(false);
const approvalAction = ref<'approve' | 'reject'>('approve');
const selectedFinding = ref<any>(null);
const showFindingModal = ref(false);

// Get current user from auth context
const { user, approverRole } = useAuth();

const loadPendingApprovals = async () => {
  loading.value = true;
  error.value = null;
  try {
    if (!approverRole.value) {
      error.value = 'You do not have permission to view approvals. You must be a Cyber Risk Manager or Data Steward.';
      loading.value = false;
      return;
    }

    const response = await axios.get('/api/finding-approvals/pending', {
      params: {
        approverRole: approverRole.value,
      },
    });
    pendingApprovals.value = response.data.map((a: any) => ({
      ...a,
      requestedAt: new Date(a.requestedAt),
      approvals: a.approvals.map((app: any) => ({
        ...app,
        approvedAt: app.approvedAt ? new Date(app.approvedAt) : undefined,
      })),
    }));
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load pending approvals';
    console.error('Failed to load pending approvals:', err);
  } finally {
    loading.value = false;
  }
};

const approveRequest = (approval: any) => {
  selectedApproval.value = approval;
  approvalAction.value = 'approve';
  showApprovalModal.value = true;
};

const rejectApproval = (approval: any) => {
  selectedApproval.value = approval;
  approvalAction.value = 'reject';
  showApprovalModal.value = true;
};

const viewFinding = async (findingId: string) => {
  try {
    const response = await axios.get(`/api/unified-findings/${findingId}`);
    selectedFinding.value = {
      ...response.data,
      createdAt: new Date(response.data.createdAt),
      updatedAt: new Date(response.data.updatedAt),
    };
    showFindingModal.value = true;
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
  padding: 24px;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0;
}

.loading,
.error {
  padding: 24px;
  text-align: center;
  color: #ffffff;
}

.error {
  color: #fc8181;
}

.empty-state {
  text-align: center;
  padding: 60px 24px;
  color: #a0aec0;
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
  gap: 20px;
}

.approval-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 24px;
}

.approval-header {
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.approval-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}

.approval-title-group h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
  flex: 1;
}

.type-badge {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
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
  gap: 12px;
}

.severity-badge {
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
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
  font-size: 0.875rem;
  color: #a0aec0;
}

.approval-body {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-bottom: 20px;
}

.approval-reason strong,
.approval-required strong,
.approval-status strong {
  display: block;
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.approval-reason p {
  color: #ffffff;
  margin: 0;
  line-height: 1.6;
}

.approvers-list {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.approver-role-badge {
  padding: 4px 12px;
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.approvers-status {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.approver-status-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 6px;
}

.approver-name {
  font-size: 0.875rem;
  color: #ffffff;
}

.status-badge {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
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
  font-size: 0.875rem;
}

.btn-link:hover {
  color: #00f2fe;
}

.approval-actions {
  display: flex;
  gap: 12px;
}

.btn-approve,
.btn-reject {
  padding: 10px 20px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  font-size: 0.875rem;
  transition: all 0.2s;
}

.btn-approve {
  background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
  color: #ffffff;
}

.btn-approve:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(34, 197, 94, 0.4);
}

.btn-reject {
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.btn-reject:hover {
  background: rgba(252, 129, 129, 0.1);
}
</style>

