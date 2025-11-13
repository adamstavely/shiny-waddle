<template>
  <div class="test-config-toggle">
    <div class="toggle-header">
      <div class="toggle-info">
        <h4 class="config-name">{{ config.name }}</h4>
        <span class="config-type">{{ config.type }}</span>
      </div>
      <div class="toggle-switch-container">
        <label class="toggle-switch">
          <input
            type="checkbox"
            :checked="config.enabled"
            @change="showToggleModal = true"
            :disabled="loading"
          />
          <span class="slider"></span>
        </label>
        <span v-if="loading" class="loading-indicator">...</span>
      </div>
    </div>
    <div v-if="config.override" class="override-info">
      <p class="override-reason" v-if="config.override.reason">
        <Info class="info-icon" />
        {{ config.override.reason }}
      </p>
      <p class="override-meta" v-if="config.override.updatedBy">
        Updated by {{ config.override.updatedBy }} on {{ formatDate(config.override.updatedAt) }}
      </p>
      <button @click="handleRemoveOverride" class="remove-override-btn" :disabled="loading">
        Remove Override
      </button>
    </div>

    <!-- Toggle Modal -->
    <Teleport to="body">
      <Transition name="fade">
        <div v-if="showToggleModal" class="modal-overlay" @click.self="showToggleModal = false">
          <div class="modal-content" @click.stop>
            <div class="modal-header">
              <h3>{{ config.enabled ? 'Disable' : 'Enable' }} Test Configuration</h3>
              <button @click="showToggleModal = false" class="close-btn">×</button>
            </div>
            <div class="modal-body">
              <p class="modal-description">
                {{ config.enabled ? 'Disable' : 'Enable' }} <strong>{{ config.name }}</strong> for this application?
              </p>
              <div class="form-group">
                <label for="reason">Reason (optional)</label>
                <textarea
                  id="reason"
                  v-model="toggleReason"
                  rows="3"
                  placeholder="Enter a reason for this change..."
                  class="reason-input"
                ></textarea>
              </div>
            </div>
            <div class="modal-actions">
              <button @click="showToggleModal = false" class="btn-secondary">Cancel</button>
              <button @click="handleToggle" class="btn-primary" :disabled="loading">
                {{ config.enabled ? 'Disable' : 'Enable' }}
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { Teleport } from 'vue';
import axios from 'axios';
import { Info } from 'lucide-vue-next';

interface Props {
  applicationId: string;
  config: {
    configId: string;
    name: string;
    type: string;
    enabled: boolean;
    override?: {
      enabled: boolean;
      reason?: string;
      updatedBy?: string;
      updatedAt?: Date;
    };
  };
}

const props = defineProps<Props>();
const emit = defineEmits<{
  (e: 'updated'): void;
}>();

const loading = ref(false);
const showToggleModal = ref(false);
const toggleReason = ref('');

const handleToggle = async () => {
  const enabled = !props.config.enabled;
  
  loading.value = true;
  try {
    await axios.patch(
      `/api/applications/${props.applicationId}/test-configurations/${props.config.configId}/toggle`,
      { enabled, reason: toggleReason.value || undefined }
    );
    showToggleModal.value = false;
    toggleReason.value = '';
    emit('updated');
  } catch (error: any) {
    console.error('Error toggling test configuration:', error);
    alert(error.response?.data?.message || 'Failed to toggle test configuration');
  } finally {
    loading.value = false;
  }
};

const handleRemoveOverride = async () => {
  if (!confirm('Remove override for this test configuration? It will revert to the default state.')) {
    return;
  }
  
  loading.value = true;
  try {
    await axios.delete(
      `/api/applications/${props.applicationId}/test-configurations/${props.config.configId}/override`
    );
    emit('updated');
  } catch (error: any) {
    console.error('Error removing override:', error);
    alert(error.response?.data?.message || 'Failed to remove override');
  } finally {
    loading.value = false;
  }
};

const formatDate = (date?: Date | string): string => {
  if (!date) return '';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString();
};
</script>

<style scoped>
.test-config-toggle {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  margin-bottom: 12px;
}

.toggle-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
}

.toggle-info {
  flex: 1;
}

.config-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.config-type {
  font-size: 0.875rem;
  color: #a0aec0;
  text-transform: uppercase;
}

.toggle-switch-container {
  display: flex;
  align-items: center;
  gap: 8px;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 48px;
  height: 24px;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: #4a5568;
  transition: 0.3s;
  border-radius: 24px;
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: 0.3s;
  border-radius: 50%;
}

input:checked + .slider {
  background-color: #4facfe;
}

input:checked + .slider:before {
  transform: translateX(24px);
}

input:disabled + .slider {
  opacity: 0.6;
  cursor: not-allowed;
}

.loading-indicator {
  color: #4facfe;
  font-size: 0.875rem;
}

.override-info {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.override-reason {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 4px 0;
  display: flex;
  align-items: center;
  gap: 6px;
}

.info-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.override-meta {
  font-size: 0.75rem;
  color: #718096;
  margin: 0;
}

.remove-override-btn {
  margin-top: 8px;
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 4px;
  color: #fc8181;
  font-size: 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
}

.remove-override-btn:hover:not(:disabled) {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.5);
}

.remove-override-btn:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  padding: 24px;
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.modal-header h3 {
  margin: 0;
  color: #ffffff;
  font-size: 1.25rem;
}

.close-btn {
  background: transparent;
  border: none;
  color: #a0aec0;
  font-size: 1.5rem;
  cursor: pointer;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.close-btn:hover {
  color: #ffffff;
}

.modal-body {
  margin-bottom: 20px;
}

.modal-description {
  color: #a0aec0;
  margin-bottom: 16px;
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  color: #ffffff;
  font-size: 0.875rem;
  margin-bottom: 8px;
}

.reason-input {
  width: 100%;
  padding: 10px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #ffffff;
  font-size: 0.875rem;
  font-family: inherit;
  resize: vertical;
}

.reason-input:focus {
  outline: none;
  border-color: rgba(79, 172, 254, 0.6);
}

.modal-actions {
  display: flex;
  gap: 12px;
  justify-content: flex-end;
}

.btn-primary {
  padding: 10px 20px;
  background: #4facfe;
  color: #ffffff;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: background 0.2s;
}

.btn-primary:hover:not(:disabled) {
  background: #3d8bfe;
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  color: #a0aec0;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.2s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

