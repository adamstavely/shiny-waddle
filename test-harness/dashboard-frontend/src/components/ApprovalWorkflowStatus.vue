<template>
  <div class="approval-status">
    <div v-if="loading" class="loading">Loading approval status...</div>
    <div v-else-if="approvalRequest">
      <div class="status-header">
        <h4>Approval Status</h4>
        <span :class="`status-badge status-${approvalRequest.status}`">
          {{ approvalRequest.status }}
        </span>
      </div>

      <div class="approval-details">
        <div class="detail-item">
          <span class="detail-label">Type:</span>
          <span class="detail-value">
            {{ approvalRequest.type === 'risk-acceptance' ? 'Risk Acceptance' : 'False Positive' }}
          </span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Requested:</span>
          <span class="detail-value">{{ formatDate(approvalRequest.requestedAt) }}</span>
        </div>
        <div class="detail-item">
          <span class="detail-label">Reason:</span>
          <span class="detail-value">{{ approvalRequest.reason }}</span>
        </div>
      </div>

      <div class="approvers-list">
        <h5>Approvers</h5>
        <div
          v-for="(approval, index) in approvalRequest.approvals"
          :key="index"
          class="approver-item"
        >
          <div class="approver-role">{{ formatRole(approval.approverRole) }}</div>
          <div :class="`approval-status-badge status-${approval.status}`">
            {{ approval.status }}
          </div>
          <div v-if="approval.comment" class="approver-comment">
            {{ approval.comment }}
          </div>
        </div>
      </div>
    </div>
    <div v-else class="no-request">
      No approval request found for this finding.
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue';
import axios from 'axios';

const props = defineProps<{
  findingId: string;
}>();

const loading = ref(true);
const approvalRequest = ref<any>(null);

const loadApprovalStatus = async () => {
  loading.value = true;
  try {
    const response = await axios.get(`/api/finding-approvals/finding/${props.findingId}`);
    if (response.data) {
      approvalRequest.value = {
        ...response.data,
        requestedAt: new Date(response.data.requestedAt),
        approvals: response.data.approvals.map((a: any) => ({
          ...a,
          approvedAt: a.approvedAt ? new Date(a.approvedAt) : undefined,
        })),
      };
    } else {
      approvalRequest.value = null;
    }
  } catch (err) {
    console.error('Failed to load approval status:', err);
    approvalRequest.value = null;
  } finally {
    loading.value = false;
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

watch(() => props.findingId, () => {
  loadApprovalStatus();
});

onMounted(() => {
  loadApprovalStatus();
});

defineExpose({
  refresh: loadApprovalStatus,
});
</script>

<style scoped>
.approval-status {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.loading,
.no-request {
  text-align: center;
  color: #a0aec0;
  padding: 20px;
}

.status-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}

.status-header h4 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.status-badge {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.status-badge.status-pending {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
  border: 1px solid rgba(251, 191, 36, 0.3);
}

.status-badge.status-approved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.status-badge.status-rejected {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.approval-details {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.detail-item {
  display: flex;
  gap: 12px;
}

.detail-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
  min-width: 100px;
}

.detail-value {
  font-size: 0.875rem;
  color: #ffffff;
}

.approvers-list h5 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 12px 0;
}

.approver-item {
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  margin-bottom: 8px;
}

.approver-role {
  font-size: 0.875rem;
  font-weight: 500;
  color: #4facfe;
  margin-bottom: 8px;
}

.approval-status-badge {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
  margin-bottom: 8px;
}

.approval-status-badge.status-pending {
  background: rgba(251, 191, 36, 0.1);
  color: #fbbf24;
}

.approval-status-badge.status-approved {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
}

.approval-status-badge.status-rejected {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
}

.approver-comment {
  font-size: 0.875rem;
  color: #a0aec0;
  font-style: italic;
  margin-top: 8px;
}
</style>

