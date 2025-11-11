<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen && run" class="modal-overlay" @click="close">
        <div class="modal-content run-details" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <GitBranch v-if="platform === 'github'" class="modal-title-icon" />
              <Settings v-else class="modal-title-icon" />
              <h2>{{ run.name }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <!-- Run Summary -->
            <div class="summary-section">
              <div class="summary-cards">
                <div class="summary-card">
                  <div class="summary-card-label">Status</div>
                  <div class="summary-card-value" :class="`status-${run.status}`">
                    {{ run.status }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Compliance Score</div>
                  <div class="summary-card-value" :class="run.compliancePassed ? 'passed' : 'failed'">
                    {{ run.complianceScore }}%
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Duration</div>
                  <div class="summary-card-value">{{ run.duration }}s</div>
                </div>
                <div class="summary-card" v-if="run.blocked">
                  <div class="summary-card-label">Blocked</div>
                  <div class="summary-card-value blocked">Yes</div>
                </div>
              </div>
            </div>

            <!-- Test Results -->
            <div v-if="run.testResults" class="section">
              <h3>Test Results</h3>
              <div class="test-results-list">
                <div
                  v-for="(test, index) in run.testResults"
                  :key="index"
                  class="test-result-item"
                  :class="{ passed: test.passed, failed: !test.passed }"
                >
                  <CheckCircle2 v-if="test.passed" class="test-icon passed" />
                  <X v-else class="test-icon failed" />
                  <div class="test-details">
                    <div class="test-name">{{ test.name }}</div>
                    <div v-if="test.error" class="test-error">{{ test.error }}</div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Logs -->
            <div v-if="run.logs" class="section">
              <h3>Logs</h3>
              <div class="logs-container">
                <pre class="logs-content">{{ run.logs }}</pre>
              </div>
            </div>

            <!-- Additional Info -->
            <div class="section">
              <h3>Details</h3>
              <div class="details-grid">
                <div class="detail-item">
                  <span class="detail-label">Started At:</span>
                  <span class="detail-value">{{ formatDate(run.startedAt) }}</span>
                </div>
                <div class="detail-item" v-if="run.completedAt">
                  <span class="detail-label">Completed At:</span>
                  <span class="detail-value">{{ formatDate(run.completedAt) }}</span>
                </div>
                <div class="detail-item" v-if="run.prNumber">
                  <span class="detail-label">PR Number:</span>
                  <span class="detail-value">#{{ run.prNumber }}</span>
                </div>
                <div class="detail-item" v-if="run.buildNumber">
                  <span class="detail-label">Build Number:</span>
                  <span class="detail-value">#{{ run.buildNumber }}</span>
                </div>
                <div class="detail-item" v-if="run.branch">
                  <span class="detail-label">Branch:</span>
                  <span class="detail-value">{{ run.branch }}</span>
                </div>
                <div class="detail-item" v-if="run.commit">
                  <span class="detail-label">Commit:</span>
                  <span class="detail-value commit-hash">{{ run.commit.substring(0, 7) }}</span>
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
import { Teleport } from 'vue';
import { GitBranch, Settings, X, CheckCircle2 } from 'lucide-vue-next';

const props = defineProps<{
  isOpen: boolean;
  run: any;
  platform: string;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
}>();

const close = () => {
  emit('update:isOpen', false);
};

const formatDate = (date: Date | string): string => {
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleString();
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

.run-details {
  max-width: 900px;
  max-height: 90vh;
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
  max-height: calc(90vh - 100px);
  overflow-y: auto;
}

.summary-section {
  margin-bottom: 24px;
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
}

.summary-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  text-align: center;
}

.summary-card-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.summary-card-value {
  font-size: 1.5rem;
  font-weight: 700;
  color: #ffffff;
}

.summary-card-value.status-success,
.summary-card-value.passed {
  color: #22c55e;
}

.summary-card-value.status-failure,
.summary-card-value.failed {
  color: #fc8181;
}

.summary-card-value.status-pending {
  color: #4facfe;
}

.summary-card-value.blocked {
  color: #fbbf24;
}

.section {
  margin-bottom: 24px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.test-results-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.test-result-item {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.8);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.test-result-item.passed {
  border-color: rgba(34, 197, 94, 0.3);
}

.test-result-item.failed {
  border-color: rgba(252, 129, 129, 0.3);
}

.test-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.test-icon.passed {
  color: #22c55e;
}

.test-icon.failed {
  color: #fc8181;
}

.test-details {
  flex: 1;
}

.test-name {
  font-size: 0.9rem;
  font-weight: 500;
  color: #ffffff;
  margin-bottom: 4px;
}

.test-error {
  font-size: 0.875rem;
  color: #fc8181;
  margin-top: 4px;
}

.logs-container {
  background: rgba(0, 0, 0, 0.3);
  border-radius: 8px;
  padding: 16px;
  overflow-x: auto;
}

.logs-content {
  margin: 0;
  color: #a0aec0;
  font-family: 'Courier New', monospace;
  font-size: 0.875rem;
  line-height: 1.6;
  white-space: pre-wrap;
  word-wrap: break-word;
}

.details-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 16px;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.detail-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.detail-value {
  font-size: 0.9rem;
  color: #ffffff;
}

.commit-hash {
  font-family: 'Courier New', monospace;
  color: #4facfe;
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

