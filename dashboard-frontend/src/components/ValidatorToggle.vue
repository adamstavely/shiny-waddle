<template>
  <div class="validator-toggle">
    <div class="toggle-header">
      <div class="toggle-info">
        <h4 class="validator-name">{{ validator.name }}</h4>
        <span class="validator-type">{{ validator.testType }}</span>
      </div>
      <div class="toggle-switch-container">
        <label class="toggle-switch">
          <input
            type="checkbox"
            :checked="validator.enabled"
            @change="showToggleModal = true"
            :disabled="loading"
          />
          <span class="slider"></span>
        </label>
        <span v-if="loading" class="loading-indicator">...</span>
      </div>
    </div>
    <div v-if="validator.override" class="override-info">
      <p class="override-reason" v-if="validator.override.reason">
        <Info class="info-icon" />
        {{ validator.override.reason }}
      </p>
      <p class="override-meta" v-if="validator.override.updatedBy">
        Updated by {{ validator.override.updatedBy }} on {{ formatDate(validator.override.updatedAt) }}
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
              <h3>{{ validator.enabled ? 'Disable' : 'Enable' }} Validator</h3>
              <button @click="showToggleModal = false" class="close-btn">×</button>
            </div>
            <div class="modal-body">
              <p class="modal-description">
                {{ validator.enabled ? 'Disable' : 'Enable' }} <strong>{{ validator.name }}</strong> for this application?
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
                {{ validator.enabled ? 'Disable' : 'Enable' }}
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
  validator: {
    validatorId: string;
    name: string;
    testType: string;
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
  const enabled = !props.validator.enabled;
  
  loading.value = true;
  try {
    await axios.patch(
      `/api/v1/applications/${props.applicationId}/validators/${props.validator.validatorId}/toggle`,
      { enabled, reason: toggleReason.value || undefined }
    );
    showToggleModal.value = false;
    toggleReason.value = '';
    emit('updated');
  } catch (error: any) {
    console.error('Error toggling validator:', error);
    alert(error.response?.data?.message || 'Failed to toggle validator');
  } finally {
    loading.value = false;
  }
};

const handleRemoveOverride = async () => {
  if (!confirm('Remove override for this validator? It will revert to the default state.')) {
    return;
  }
  
  loading.value = true;
  try {
    await axios.delete(
      `/api/v1/applications/${props.applicationId}/validators/${props.validator.validatorId}/override`
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
.validator-toggle {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  margin-bottom: var(--spacing-sm);
}

.toggle-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: var(--spacing-md);
}

.toggle-info {
  flex: 1;
}

.validator-name {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.validator-type {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  text-transform: uppercase;
}

.toggle-switch-container {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
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
  background-color: var(--color-bg-tertiary);
  transition: var(--transition-all);
  border-radius: var(--border-radius-xl);
}

.slider:before {
  position: absolute;
  content: "";
  height: 18px;
  width: 18px;
  left: 3px;
  bottom: 3px;
  background-color: white;
  transition: var(--transition-all);
  border-radius: 50%;
}

input:checked + .slider {
  background-color: var(--color-primary);
}

input:checked + .slider:before {
  transform: translateX(24px);
}

input:disabled + .slider {
  opacity: 0.6;
  cursor: not-allowed;
}

.loading-indicator {
  color: var(--color-primary);
  font-size: var(--font-size-sm);
}

.override-info {
  margin-top: var(--spacing-sm);
  padding-top: var(--spacing-sm);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.override-reason {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-xs) 0;
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.info-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.override-meta {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
  margin: 0;
}

.remove-override-btn {
  margin-top: var(--spacing-sm);
  padding: var(--spacing-xs) var(--spacing-sm);
  background: transparent;
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  color: var(--color-error);
  font-size: var(--font-size-xs);
  cursor: pointer;
  transition: all 0.2s;
}

.remove-override-btn:hover:not(:disabled) {
  background: var(--color-error-bg);
  border-color: var(--color-error);
  opacity: 0.5;
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
  background: var(--color-bg-overlay-dark);
  opacity: 0.7;
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
  max-width: 500px;
  width: 90%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.modal-header h3 {
  margin: 0;
  color: var(--color-text-primary);
  font-size: var(--font-size-xl);
}

.close-btn {
  background: transparent;
  border: none;
  color: var(--color-text-secondary);
  font-size: var(--font-size-2xl);
  cursor: pointer;
  padding: 0;
  width: 30px;
  height: 30px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.close-btn:hover {
  color: var(--color-text-primary);
}

.modal-body {
  margin-bottom: var(--spacing-lg);
}

.modal-description {
  color: var(--color-text-secondary);
  margin-bottom: 16px;
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-sm);
}

.reason-input {
  width: 100%;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-dark);
  opacity: 0.3;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  font-family: inherit;
  resize: vertical;
}

.reason-input:focus {
  outline: none;
  border-color: var(--border-color-primary-active);
}

.modal-actions {
  display: flex;
  gap: var(--spacing-sm);
  justify-content: flex-end;
}

.btn-primary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--color-primary);
  color: var(--color-text-primary);
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: var(--font-weight-medium);
  transition: var(--transition-all);
}

.btn-primary:hover:not(:disabled) {
  background: var(--color-primary-dark);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  color: var(--color-text-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.3;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
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

