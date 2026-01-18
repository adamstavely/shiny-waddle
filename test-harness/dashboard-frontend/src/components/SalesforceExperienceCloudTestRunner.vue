<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>Run Salesforce Experience Cloud Test</h2>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleSubmit">
              <div class="form-group">
                <label>Configuration *</label>
                <select v-model="testForm.configId" required class="form-input">
                  <option value="">Select a configuration</option>
                  <option v-for="config in configs" :key="config.id" :value="config.id">
                    {{ config.name }} ({{ config.url }})
                  </option>
                </select>
              </div>

              <div class="form-group">
                <label>Test Type *</label>
                <select v-model="testForm.testType" required class="form-input">
                  <option value="guest-access">Guest Access</option>
                  <option value="authenticated-access">Authenticated Access</option>
                  <option value="graphql">GraphQL Capability</option>
                  <option value="self-registration">Self-Registration</option>
                  <option value="record-lists">Record List Components</option>
                  <option value="home-urls">Home URLs</option>
                  <option value="object-access">Object Access</option>
                  <option value="full-audit">Full Audit</option>
                </select>
              </div>

              <div v-if="testForm.testType === 'authenticated-access'" class="form-group">
                <label>Cookies (optional override)</label>
                <textarea
                  v-model="testForm.cookies"
                  class="form-input"
                  rows="3"
                  placeholder="Leave empty to use configuration cookies"
                ></textarea>
              </div>

              <div v-if="testForm.testType === 'object-access'" class="form-group">
                <label>Objects *</label>
                <input
                  v-model="objectListString"
                  type="text"
                  required
                  class="form-input"
                  placeholder="Account, Contact, Opportunity"
                />
                <small class="form-hint">Comma-separated list of Salesforce objects to test</small>
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="cancel-btn">Cancel</button>
                <button type="submit" class="run-btn" :disabled="running">
                  <Loader2 v-if="running" class="btn-icon spin" />
                  <Play v-else class="btn-icon" />
                  {{ running ? 'Running...' : 'Run Test' }}
                </button>
              </div>
            </form>

            <div v-if="testResult" class="test-result">
              <h3>Test Result</h3>
              <div class="result-summary">
                <div class="result-status" :class="`status-${testResult.status}`">
                  {{ testResult.status }}
                </div>
                <div class="result-info">
                  <p><strong>Test:</strong> {{ testResult.testName }}</p>
                  <p v-if="testResult.summary">
                    <strong>Findings:</strong> {{ testResult.summary.totalFindings }}
                    ({{ testResult.summary.criticalCount }} critical, {{ testResult.summary.highCount }} high)
                  </p>
                  <p v-if="testResult.error" class="error-text">
                    <strong>Error:</strong> {{ testResult.error }}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { X, Play, Loader2 } from 'lucide-vue-next';
import axios from 'axios';
import type {
  SalesforceExperienceCloudConfigEntity,
  SalesforceExperienceCloudTestResultEntity,
} from '../types/salesforce-experience-cloud';

interface Props {
  show: boolean;
  configs: SalesforceExperienceCloudConfigEntity[];
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  testComplete: [];
}>();

const running = ref(false);
const testResult = ref<SalesforceExperienceCloudTestResultEntity | null>(null);
const testForm = ref({
  configId: '',
  testType: 'guest-access',
  cookies: '',
  objects: [] as string[],
});

const objectListString = computed({
  get: () => testForm.value.objects?.join(', ') || '',
  set: (value: string) => {
    testForm.value.objects = value
      ? value.split(',').map(s => s.trim()).filter(s => s.length > 0)
      : [];
  },
});

const handleSubmit = async () => {
  running.value = true;
  testResult.value = null;

  try {
    const baseUrl = '/api/salesforce-experience-cloud/tests';
    let response;

    switch (testForm.value.testType) {
      case 'guest-access':
        response = await axios.post(`${baseUrl}/guest-access`, {
          configId: testForm.value.configId,
        });
        break;
      case 'authenticated-access':
        response = await axios.post(`${baseUrl}/authenticated-access`, {
          configId: testForm.value.configId,
          cookies: testForm.value.cookies || undefined,
        });
        break;
      case 'graphql':
        response = await axios.post(`${baseUrl}/graphql`, {
          configId: testForm.value.configId,
        });
        break;
      case 'self-registration':
        response = await axios.post(`${baseUrl}/self-registration`, {
          configId: testForm.value.configId,
        });
        break;
      case 'record-lists':
        response = await axios.post(`${baseUrl}/record-lists`, {
          configId: testForm.value.configId,
        });
        break;
      case 'home-urls':
        response = await axios.post(`${baseUrl}/home-urls`, {
          configId: testForm.value.configId,
        });
        break;
      case 'object-access':
        if (testForm.value.objects.length === 0) {
          alert('Please specify at least one object');
          return;
        }
        response = await axios.post(`${baseUrl}/object-access`, {
          configId: testForm.value.configId,
          objects: testForm.value.objects,
        });
        break;
      case 'full-audit':
        response = await axios.post(`${baseUrl}/full-audit`, {
          configId: testForm.value.configId,
        });
        // Full audit returns array
        if (Array.isArray(response.data) && response.data.length > 0) {
          testResult.value = response.data[0]; // Show first result
        }
        break;
    }

    if (!Array.isArray(response.data)) {
      testResult.value = response.data;
    }

    // Wait a bit before emitting complete to show result
    setTimeout(() => {
      emit('testComplete');
    }, 2000);
  } catch (error: any) {
    console.error('Error running test:', error);
    alert(error.response?.data?.message || 'Failed to run test');
  } finally {
    running.value = false;
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
  background: rgba(0, 0, 0, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: var(--card-bg);
  border-radius: 8px;
  max-width: 600px;
  width: 100%;
  max-height: 90vh;
  overflow-y: auto;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  border-bottom: 1px solid var(--border-color);
}

.modal-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.modal-close {
  background: none;
  border: none;
  cursor: pointer;
  padding: 4px;
  color: var(--text-secondary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 20px;
}

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 6px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text-primary);
}

.form-input {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--border-color);
  border-radius: 6px;
  font-size: 14px;
  font-family: inherit;
}

.form-input:focus {
  outline: none;
  border-color: var(--primary-color);
}

.form-hint {
  display: block;
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-secondary);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 20px;
  border-top: 1px solid var(--border-color);
}

.cancel-btn,
.run-btn {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border: none;
  border-radius: 6px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.cancel-btn {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 1px solid var(--border-color);
}

.cancel-btn:hover {
  background: var(--bg-tertiary);
}

.run-btn {
  background: var(--primary-color);
  color: white;
}

.run-btn:hover:not(:disabled) {
  background: var(--primary-color-dark);
}

.run-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-icon {
  width: 16px;
  height: 16px;
}

.spin {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.test-result {
  margin-top: 24px;
  padding: 16px;
  background: var(--bg-secondary);
  border-radius: 6px;
}

.test-result h3 {
  margin: 0 0 12px 0;
  font-size: 16px;
  font-weight: 600;
}

.result-summary {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.result-status {
  display: inline-block;
  padding: 6px 12px;
  border-radius: 4px;
  font-size: 14px;
  font-weight: 600;
  text-transform: uppercase;
  width: fit-content;
}

.status-passed {
  background: var(--success-bg);
  color: var(--success-color);
}

.status-failed {
  background: var(--error-bg);
  color: var(--error-color);
}

.status-warning {
  background: var(--warning-bg);
  color: var(--warning-color);
}

.result-info {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.result-info p {
  margin: 0;
  font-size: 14px;
}

.error-text {
  color: var(--error-color);
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
