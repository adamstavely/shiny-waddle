<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>{{ action === 'approve' ? 'Approve Request' : 'Reject Request' }}</h2>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <div class="approval-info">
              <div class="info-item">
                <span class="info-label">Finding:</span>
                <span class="info-value">{{ approval.metadata?.findingTitle || 'Unknown' }}</span>
              </div>
              <div class="info-item">
                <span class="info-label">Type:</span>
                <span class="info-value">
                  {{ approval.type === 'risk-acceptance' ? 'Risk Acceptance' : 'False Positive' }}
                </span>
              </div>
              <div class="info-item">
                <span class="info-label">Reason:</span>
                <span class="info-value">{{ approval.reason }}</span>
              </div>
            </div>

            <div class="form-group">
              <label for="comment">Comment {{ action === 'reject' ? '*' : '' }}</label>
              <textarea
                id="comment"
                v-model="comment"
                rows="4"
                :placeholder="action === 'approve' ? 'Optional comment...' : 'Required: Explain why you are rejecting this request...'"
                class="form-textarea"
                :required="action === 'reject'"
              />
            </div>

            <div v-if="error" class="error-message">{{ error }}</div>
          </div>

          <div class="modal-footer">
            <button @click="close" class="btn-secondary">Cancel</button>
            <button
              @click="submitAction"
              class="btn-primary"
              :class="action === 'reject' ? 'btn-reject' : 'btn-approve'"
              :disabled="(action === 'reject' && !comment.trim()) || submitting"
            >
              {{ submitting ? 'Processing...' : action === 'approve' ? 'Approve' : 'Reject' }}
            </button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { X } from 'lucide-vue-next';
import axios from 'axios';
import { useAuth } from '../composables/useAuth';

const props = defineProps<{
  isOpen: boolean;
  approval: any;
  action: 'approve' | 'reject';
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'submitted': [];
}>();

const comment = ref('');
const submitting = ref(false);
const error = ref<string | null>(null);

const close = () => {
  comment.value = '';
  error.value = null;
  emit('update:isOpen', false);
};

const submitAction = async () => {
  if (props.action === 'reject' && !comment.value.trim()) {
    error.value = 'Comment is required when rejecting';
    return;
  }

  submitting.value = true;
  error.value = null;

  try {
    const { user, approverRole } = useAuth();

    if (!approverRole.value) {
      error.value = 'You do not have permission to approve requests';
      submitting.value = false;
      return;
    }

    if (props.action === 'approve') {
      await axios.patch(`/api/finding-approvals/${props.approval.id}/approve`, {
        comment: comment.value.trim() || undefined,
      });
    } else {
      await axios.patch(`/api/finding-approvals/${props.approval.id}/reject`, {
        comment: comment.value.trim(),
      });
    }

    emit('submitted');
    close();
  } catch (err: any) {
    error.value = err.response?.data?.message || `Failed to ${props.action} request`;
    console.error(`Failed to ${props.action} request:`, err);
  } finally {
    submitting.value = false;
  }
};
</script>

<style scoped>
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
  background: rgba(15, 20, 25, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
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
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
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

.approval-info {
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 20px;
}

.info-item {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}

.info-item:last-child {
  margin-bottom: 0;
}

.info-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
  min-width: 80px;
}

.info-value {
  font-size: 0.875rem;
  color: #ffffff;
  flex: 1;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #ffffff;
  margin-bottom: 8px;
}

.form-textarea {
  width: 100%;
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
  resize: vertical;
}

.form-textarea:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.5);
}

.error-message {
  padding: 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  color: #fc8181;
  font-size: 0.875rem;
  margin-top: 16px;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
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

.btn-primary.btn-approve {
  background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
  color: #ffffff;
}

.btn-primary.btn-reject {
  background: linear-gradient(135deg, #fc8181 0%, #f87171 100%);
  color: #ffffff;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.5;
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

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

