<template>
  <div v-if="isOpen" class="modal-overlay" @click.self="close">
    <div class="modal-content">
      <div class="modal-header">
        <div class="modal-header-title">
          <FileText class="modal-header-icon" />
          <h2>Test Result Details</h2>
        </div>
        <button @click="close" class="close-btn">×</button>
      </div>
      
      <div v-if="result" class="modal-body">
        <!-- Metadata Section -->
        <div class="detail-section">
          <h3 class="section-title">Metadata</h3>
          <div class="detail-grid">
            <div class="detail-item">
              <span class="detail-label">Application</span>
              <span class="detail-value">{{ result.applicationName }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Test Configuration</span>
              <span class="detail-value">{{ result.testConfigurationName }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Type</span>
              <span class="detail-value">{{ result.testConfigurationType }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Status</span>
              <span class="status-badge" :class="`status-${result.status}`">
                {{ result.status }}
              </span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Timestamp</span>
              <span class="detail-value">{{ formatDateTime(result.timestamp) }}</span>
            </div>
            <div class="detail-item" v-if="result.duration">
              <span class="detail-label">Duration</span>
              <span class="detail-value">{{ formatDuration(result.duration) }}</span>
            </div>
            <div class="detail-item" v-if="result.buildId">
              <span class="detail-label">Build ID</span>
              <span class="detail-value build-id">{{ result.buildId }}</span>
            </div>
            <div class="detail-item" v-if="result.runId">
              <span class="detail-label">Run ID</span>
              <span class="detail-value">{{ result.runId }}</span>
            </div>
            <div class="detail-item" v-if="result.commitSha">
              <span class="detail-label">Commit SHA</span>
              <span class="detail-value commit-sha">{{ result.commitSha }}</span>
            </div>
            <div class="detail-item" v-if="result.branch">
              <span class="detail-label">Branch</span>
              <span class="detail-value">{{ result.branch }}</span>
            </div>
          </div>
        </div>

        <!-- Error Section -->
        <div v-if="result.error" class="detail-section">
          <h3 class="section-title">Error Details</h3>
          <div class="error-box">
            <div class="error-type">{{ result.error.type }}</div>
            <div class="error-message">{{ result.error.message }}</div>
            <div v-if="result.error.details" class="error-details">
              <pre>{{ JSON.stringify(result.error.details, null, 2) }}</pre>
            </div>
          </div>
        </div>

        <!-- Result Section -->
        <div class="detail-section">
          <h3 class="section-title">Test Result</h3>
          <div class="result-box">
            <pre class="result-json">{{ formatResult(result.result) }}</pre>
          </div>
        </div>

        <!-- Metadata Section -->
        <div v-if="result.metadata && Object.keys(result.metadata).length > 0" class="detail-section">
          <h3 class="section-title">Additional Metadata</h3>
          <div class="result-box">
            <pre class="result-json">{{ JSON.stringify(result.metadata, null, 2) }}</pre>
          </div>
        </div>
      </div>

      <div class="modal-footer">
        <button @click="close" class="btn-secondary">Close</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { FileText } from 'lucide-vue-next';
import type { TestResult } from '../types/test-results';

const props = defineProps<{
  isOpen: boolean;
  result: TestResult | null;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'close': [];
}>();

const close = () => {
  emit('update:isOpen', false);
  emit('close');
};

const formatDateTime = (date: Date | string) => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatDuration = (ms: number) => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
};

const formatResult = (result: any) => {
  if (!result) return 'No result data';
  return JSON.stringify(result, null, 2);
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
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 90%;
  max-width: 1000px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.modal-header-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.modal-header h2 {
  margin: 0;
  font-size: 1.5rem;
  color: #ffffff;
  font-weight: 600;
}

.close-btn {
  background: transparent;
  border: none;
  font-size: 2rem;
  cursor: pointer;
  color: #a0aec0;
  line-height: 1;
  padding: 0;
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  transition: all 0.2s;
}

.close-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.modal-body {
  padding: 1.5rem;
  overflow-y: auto;
  flex: 1;
}

.detail-section {
  margin-bottom: 2rem;
}

.section-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 1rem;
  padding-bottom: 0.5rem;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.detail-label {
  font-size: 0.75rem;
  color: #718096;
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.detail-value {
  font-size: 0.875rem;
  color: #e2e8f0;
  font-weight: 500;
}

.status-badge {
  display: inline-block;
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  width: fit-content;
}

.status-passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.status-partial {
  background: rgba(237, 137, 54, 0.2);
  color: #ed8936;
  border: 1px solid rgba(237, 137, 54, 0.3);
}

.status-error {
  background: rgba(245, 101, 101, 0.2);
  color: #f56565;
  border: 1px solid rgba(245, 101, 101, 0.3);
}

.build-id,
.commit-sha {
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
  display: inline-block;
}

.error-box {
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 8px;
  padding: 1rem;
}

.error-type {
  font-size: 0.875rem;
  font-weight: 600;
  color: #fc8181;
  margin-bottom: 0.5rem;
}

.error-message {
  font-size: 0.875rem;
  color: #e2e8f0;
  margin-bottom: 0.75rem;
}

.error-details {
  margin-top: 0.75rem;
  padding-top: 0.75rem;
  border-top: 1px solid rgba(252, 129, 129, 0.2);
}

.error-details pre {
  margin: 0;
  font-size: 0.75rem;
  color: #a0aec0;
  overflow-x: auto;
}

.result-box {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  max-height: 400px;
  overflow: auto;
}

.result-json {
  margin: 0;
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  color: #e2e8f0;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.modal-footer {
  padding: 1.5rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  justify-content: flex-end;
}

.btn-secondary {
  padding: 0.75rem 1.5rem;
  background: rgba(79, 172, 254, 0.1);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
}
</style>
