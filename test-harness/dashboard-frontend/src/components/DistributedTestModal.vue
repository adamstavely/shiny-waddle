<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Play class="modal-title-icon" />
              <h2>Run Distributed Systems Test</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleRunTest">
              <div class="form-group">
                <label>Test Name *</label>
                <input
                  v-model="form.name"
                  type="text"
                  placeholder="Enter test name"
                  class="form-input"
                  required
                />
              </div>

              <div class="form-group">
                <label>Test Type *</label>
                <Dropdown
                  v-model="form.testType"
                  :options="testTypeOptions"
                  placeholder="Select test type"
                  class="form-dropdown"
                />
              </div>

              <div class="form-group" v-if="regions && regions.length > 0">
                <label>Regions (Optional - leave empty for all)</label>
                <div class="checkbox-group">
                  <label
                    v-for="region in regions"
                    :key="region.id"
                    class="checkbox-option"
                  >
                    <input
                      v-model="form.regions"
                      type="checkbox"
                      :value="region.id"
                      class="checkbox-input"
                    />
                    <span>{{ region.name }}</span>
                  </label>
                </div>
              </div>

              <div class="form-group">
                <label>User ID</label>
                <input
                  v-model="form.userId"
                  type="text"
                  placeholder="user-123"
                  class="form-input"
                />
              </div>

              <div class="form-group">
                <label>Resource ID</label>
                <input
                  v-model="form.resourceId"
                  type="text"
                  placeholder="resource-456"
                  class="form-input"
                />
              </div>

              <div class="form-group">
                <label>Action</label>
                <input
                  v-model="form.action"
                  type="text"
                  placeholder="read, write, delete"
                  class="form-input"
                />
              </div>

              <div class="form-group">
                <label>Timeout (ms)</label>
                <input
                  v-model.number="form.timeout"
                  type="number"
                  min="1000"
                  placeholder="10000"
                  class="form-input"
                />
              </div>

              <div class="modal-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="isRunning">
                  <Loader2 v-if="isRunning" class="btn-icon spinning" />
                  <Play v-else class="btn-icon" />
                  {{ isRunning ? 'Running Test...' : 'Run Test' }}
                </button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { Teleport } from 'vue';
import { Play, X, Loader2 } from 'lucide-vue-next';
import axios from 'axios';
import Dropdown from './Dropdown.vue';

const props = defineProps<{
  isOpen: boolean;
  regions?: any[];
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'test-executed': [];
}>();

const isRunning = ref(false);

const form = ref({
  name: '',
  testType: '',
  regions: [] as string[],
  userId: '',
  resourceId: '',
  action: '',
  timeout: 10000,
});

const testTypeOptions = [
  { label: 'Policy Consistency', value: 'policy-consistency' },
  { label: 'Multi-Region', value: 'multi-region' },
  { label: 'Synchronization', value: 'synchronization' },
  { label: 'Transaction', value: 'transaction' },
  { label: 'Eventual Consistency', value: 'eventual-consistency' },
];

watch(() => props.isOpen, (newVal) => {
  if (newVal) {
    form.value = {
      name: '',
      testType: '',
      regions: [],
      userId: '',
      resourceId: '',
      action: '',
      timeout: 10000,
    };
  }
});

const close = () => {
  emit('update:isOpen', false);
};

const handleRunTest = async () => {
  isRunning.value = true;
  try {
    const payload: any = {
      name: form.value.name,
      testType: form.value.testType,
      timeout: form.value.timeout,
    };

    if (form.value.regions.length > 0) {
      payload.regions = form.value.regions;
    }

    if (form.value.userId) {
      payload.user = { id: form.value.userId };
    }

    if (form.value.resourceId) {
      payload.resource = { id: form.value.resourceId };
    }

    if (form.value.action) {
      payload.action = form.value.action;
    }

    await axios.post('/api/distributed-systems/tests/run', payload);
    emit('test-executed');
    close();
  } catch (error) {
    console.error('Failed to run test:', error);
    alert('Failed to run test. Please try again.');
  } finally {
    isRunning.value = false;
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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
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
  display: flex;
  align-items: center;
  justify-content: center;
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
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-dropdown {
  width: 100%;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
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

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
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

.btn-icon {
  width: 18px;
  height: 18px;
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
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

