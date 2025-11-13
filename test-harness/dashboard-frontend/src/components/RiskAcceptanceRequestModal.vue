<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>{{ type === 'risk-acceptance' ? 'Request Risk Acceptance' : 'Mark as False Positive' }}</h2>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <div class="form-group">
              <label>Finding</label>
              <div class="finding-info">
                <strong>{{ finding?.title }}</strong>
                <span :class="`severity-badge severity-${finding?.severity}`">
                  {{ finding?.severity }}
                </span>
              </div>
            </div>

            <div class="form-group">
              <label for="reason">Reason *</label>
              <textarea
                id="reason"
                v-model="reason"
                rows="4"
                placeholder="Explain why you want to request risk acceptance or mark this as a false positive..."
                class="form-textarea"
                required
              />
            </div>

            <div v-if="error" class="error-message">{{ error }}</div>
          </div>

          <div class="modal-footer">
            <button @click="close" class="btn-secondary">Cancel</button>
            <button @click="submitRequest" class="btn-primary" :disabled="!reason.trim() || submitting">
              {{ submitting ? 'Submitting...' : 'Submit Request' }}
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
  finding: any;
  type: 'risk-acceptance' | 'false-positive';
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'submitted': [];
}>();

const reason = ref('');
const submitting = ref(false);
const error = ref<string | null>(null);

const close = () => {
  reason.value = '';
  error.value = null;
  emit('update:isOpen', false);
};

const { user } = useAuth();

const submitRequest = async () => {
  if (!reason.value.trim()) {
    error.value = 'Reason is required';
    return;
  }

  submitting.value = true;
  error.value = null;

  try {
    await axios.post('/api/finding-approvals/request', {
      findingId: props.finding.id,
      type: props.type,
      reason: reason.value,
    });

    emit('submitted');
    close();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to submit request';
    console.error('Failed to submit approval request:', err);
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

.finding-info {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
}

.finding-info strong {
  color: #ffffff;
  flex: 1;
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

