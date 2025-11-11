<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Play class="modal-title-icon" />
              <h2>{{ execution?.suiteName }}</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body" v-if="execution">
            <!-- Status Badge -->
            <div class="status-badge-section">
              <span class="status-badge" :class="`status-${execution.status}`">
                {{ execution.status }}
              </span>
              <span class="score-badge" :class="getScoreClass(execution.score)">
                {{ execution.score }}% compliance
              </span>
            </div>

            <!-- Basic Information -->
            <div class="detail-section">
              <h3 class="section-title">Execution Details</h3>
              <div class="info-grid">
                <div class="info-item">
                  <span class="info-label">Timestamp</span>
                  <span class="info-value">{{ formatDateTime(execution.timestamp) }}</span>
                </div>
                <div class="info-item" v-if="execution.application">
                  <span class="info-label">Application</span>
                  <span class="info-value">{{ execution.application }}</span>
                </div>
                <div class="info-item" v-if="execution.team">
                  <span class="info-label">Team</span>
                  <span class="info-value">{{ execution.team }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Total Tests</span>
                  <span class="info-value">{{ execution.testCount }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Passed</span>
                  <span class="info-value passed">{{ execution.passedCount }}</span>
                </div>
                <div class="info-item">
                  <span class="info-label">Failed</span>
                  <span class="info-value failed">{{ execution.failedCount }}</span>
                </div>
                <div class="info-item" v-if="execution.duration">
                  <span class="info-label">Duration</span>
                  <span class="info-value">{{ formatDuration(execution.duration) }}</span>
                </div>
              </div>
            </div>

            <!-- Test Results -->
            <div class="detail-section" v-if="execution.testResults && execution.testResults.length > 0">
              <h3 class="section-title">Test Results</h3>
              <div class="test-results-list">
                <div
                  v-for="result in execution.testResults"
                  :key="result.id"
                  class="test-result-item"
                  :class="`result-${result.status}`"
                >
                  <div class="result-header">
                    <span class="result-name">{{ result.testName }}</span>
                    <span class="result-status">{{ result.status }}</span>
                  </div>
                  <div class="result-meta">
                    <span class="result-duration">{{ formatDuration(result.duration) }}</span>
                    <span v-if="result.error" class="result-error">{{ result.error }}</span>
                  </div>
                  <div v-if="result.details" class="result-details">
                    <pre>{{ JSON.stringify(result.details, null, 2) }}</pre>
                  </div>
                </div>
              </div>
            </div>

            <!-- Metadata -->
            <div class="detail-section" v-if="execution.metadata && Object.keys(execution.metadata).length > 0">
              <h3 class="section-title">Metadata</h3>
              <pre class="metadata-preview">{{ JSON.stringify(execution.metadata, null, 2) }}</pre>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { Play, X } from 'lucide-vue-next';
import type { TestExecutionEntity } from '../types/history';

interface Props {
  show: boolean;
  execution: TestExecutionEntity | null;
}

defineProps<Props>();
defineEmits<{
  close: [];
}>();

const formatDateTime = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
};

const formatDuration = (ms: number): string => {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
};

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-high';
  if (score >= 70) return 'score-medium';
  return 'score-low';
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
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
  width: 28px;
  height: 28px;
  color: #4facfe;
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
  border-radius: 8px;
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

.status-badge-section {
  display: flex;
  gap: 12px;
  margin-bottom: 24px;
}

.status-badge {
  padding: 6px 16px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-completed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-running {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.score-badge {
  padding: 6px 16px;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 600;
}

.score-high {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.score-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.score-low {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.detail-section {
  margin-bottom: 32px;
}

.section-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.info-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value {
  font-size: 0.9rem;
  color: #ffffff;
}

.info-value.passed {
  color: #22c55e;
}

.info-value.failed {
  color: #fc8181;
}

.test-results-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.test-result-item {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 12px 16px;
}

.test-result-item.result-passed {
  border-left: 4px solid #22c55e;
}

.test-result-item.result-failed {
  border-left: 4px solid #fc8181;
}

.test-result-item.result-skipped {
  border-left: 4px solid #fbbf24;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.result-name {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.result-status {
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
  padding: 4px 8px;
  border-radius: 6px;
}

.result-passed .result-status {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.result-failed .result-status {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.result-skipped .result-status {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.result-meta {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #718096;
  margin-bottom: 8px;
}

.result-error {
  color: #fc8181;
}

.result-details {
  margin-top: 8px;
  padding: 8px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 4px;
}

.result-details pre {
  margin: 0;
  color: #a0aec0;
  font-size: 0.75rem;
  font-family: 'Courier New', monospace;
  overflow-x: auto;
}

.metadata-preview {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
  color: #a0aec0;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

