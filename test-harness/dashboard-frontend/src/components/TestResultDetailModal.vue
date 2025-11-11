<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="close">
        <div class="modal-content large-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <div>
                <h2>Test Result Details</h2>
                <p class="result-subtitle">{{ result?.testName }}</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          
          <div class="modal-body" v-if="result">
            <div class="result-summary">
              <div class="status-badge" :class="result.passed ? 'status-passed' : 'status-failed'">
                <CheckCircle2 v-if="result.passed" class="status-icon" />
                <XCircle v-else class="status-icon" />
                {{ result.passed ? 'Passed' : 'Failed' }}
              </div>
              <div class="result-meta-info">
                <div class="meta-item">
                  <span class="meta-label">Test Type:</span>
                  <span class="meta-value">{{ formatTestType(result.testType) }}</span>
                </div>
                <div class="meta-item">
                  <span class="meta-label">Timestamp:</span>
                  <span class="meta-value">{{ formatTimestamp(result.timestamp) }}</span>
                </div>
                <div class="meta-item" v-if="result.validatorName">
                  <span class="meta-label">Validator:</span>
                  <span class="meta-value">{{ result.validatorName }}</span>
                </div>
              </div>
            </div>

            <div v-if="result.error" class="error-section">
              <h3 class="section-title">
                <AlertTriangle class="section-icon error" />
                Error Details
              </h3>
              <div class="error-content">
                <pre>{{ result.error }}</pre>
              </div>
            </div>

            <div v-if="result.details" class="details-section">
              <h3 class="section-title">
                <Info class="section-icon" />
                Test Details
              </h3>
              <div class="details-content">
                <pre>{{ JSON.stringify(result.details, null, 2) }}</pre>
              </div>
            </div>

            <div v-if="previousResult" class="comparison-section">
              <h3 class="section-title">
                <TrendingUp class="section-icon" />
                Comparison with Previous Run
              </h3>
              <div class="comparison-content">
                <div class="comparison-row">
                  <div class="comparison-item">
                    <span class="comparison-label">Previous Status:</span>
                    <span class="comparison-value" :class="previousResult.passed ? 'status-passed' : 'status-failed'">
                      {{ previousResult.passed ? 'Passed' : 'Failed' }}
                    </span>
                  </div>
                  <div class="comparison-item">
                    <span class="comparison-label">Previous Time:</span>
                    <span class="comparison-value">{{ formatTimestamp(previousResult.timestamp) }}</span>
                  </div>
                </div>
              </div>
            </div>

            <div class="actions-section">
              <button @click="exportResult" class="btn-secondary">
                <Download class="btn-icon" />
                Export Result
              </button>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { Teleport } from 'vue';
import {
  FileText,
  X,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  TrendingUp,
  Download
} from 'lucide-vue-next';

interface TestResult {
  id: string;
  testName: string;
  testType: string;
  passed: boolean;
  timestamp: Date;
  error?: string;
  details?: any;
  validatorName?: string;
  validatorId?: string;
}

interface Props {
  show: boolean;
  result: TestResult | null;
  previousResult?: TestResult | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  export: [result: TestResult];
}>();

function close() {
  emit('close');
}

function formatTestType(type: string): string {
  return type.split('-').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1)
  ).join(' ');
}

function formatTimestamp(timestamp: Date): string {
  return new Date(timestamp).toLocaleString();
}

function exportResult() {
  if (props.result) {
    emit('export', props.result);
  }
}
</script>

<style scoped>
.large-modal {
  max-width: 800px;
}

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
  align-items: flex-start;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  position: sticky;
  top: 0;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  z-index: 10;
}

.modal-title-group {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  flex: 1;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
  margin-top: 4px;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.result-subtitle {
  font-size: 0.875rem;
  color: #a0aec0;
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

.result-summary {
  margin-bottom: 24px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
}

.status-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 8px;
  font-weight: 600;
  font-size: 0.9rem;
  margin-bottom: 16px;
}

.status-passed {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.status-icon {
  width: 18px;
  height: 18px;
}

.result-meta-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.meta-item {
  display: flex;
  gap: 12px;
}

.meta-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
  min-width: 100px;
}

.meta-value {
  font-size: 0.875rem;
  color: #ffffff;
}

.error-section,
.details-section,
.comparison-section {
  margin-bottom: 24px;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 1.1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.section-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
}

.section-icon.error {
  color: #fc8181;
}

.error-content,
.details-content {
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  border-left: 3px solid #fc8181;
}

.error-content pre,
.details-content pre {
  margin: 0;
  color: #fc8181;
  font-size: 0.875rem;
  font-family: 'Courier New', monospace;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.details-content {
  border-left-color: #4facfe;
}

.details-content pre {
  color: #a0aec0;
}

.comparison-content {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.comparison-row {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
}

.comparison-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.comparison-label {
  font-size: 0.75rem;
  color: #718096;
}

.comparison-value {
  font-size: 0.9rem;
  font-weight: 600;
  color: #ffffff;
}

.actions-section {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  background: transparent;
  border: 2px solid rgba(79, 172, 254, 0.3);
  border-radius: 12px;
  color: #4facfe;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-icon {
  width: 18px;
  height: 18px;
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

