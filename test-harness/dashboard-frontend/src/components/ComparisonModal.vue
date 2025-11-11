<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <GitCompare class="modal-title-icon" />
              <h2>Execution Comparison</h2>
            </div>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body" v-if="comparison">
            <!-- Comparison Summary -->
            <div class="comparison-summary">
              <div class="summary-item">
                <span class="summary-label">Score Change</span>
                <span class="summary-value" :class="getDiffClass(comparison.differences.score)">
                  {{ formatDiff(comparison.differences.score) }}%
                </span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Test Count Change</span>
                <span class="summary-value" :class="getDiffClass(comparison.differences.testCount)">
                  {{ formatDiff(comparison.differences.testCount) }}
                </span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Passed Change</span>
                <span class="summary-value" :class="getDiffClass(comparison.differences.passedCount)">
                  {{ formatDiff(comparison.differences.passedCount) }}
                </span>
              </div>
              <div class="summary-item">
                <span class="summary-label">Failed Change</span>
                <span class="summary-value" :class="getDiffClass(-comparison.differences.failedCount)">
                  {{ formatDiff(-comparison.differences.failedCount) }}
                </span>
              </div>
            </div>

            <!-- Side by Side Comparison -->
            <div class="comparison-grid">
              <div class="comparison-column">
                <h3 class="column-title">Execution 1</h3>
                <div class="execution-info">
                  <div class="info-row">
                    <span class="info-label">Suite Name</span>
                    <span class="info-value">{{ comparison.execution1.suiteName }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Timestamp</span>
                    <span class="info-value">{{ formatDateTime(comparison.execution1.timestamp) }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Score</span>
                    <span class="info-value" :class="getScoreClass(comparison.execution1.score)">
                      {{ comparison.execution1.score }}%
                    </span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Tests</span>
                    <span class="info-value">{{ comparison.execution1.testCount }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Passed</span>
                    <span class="info-value passed">{{ comparison.execution1.passedCount }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Failed</span>
                    <span class="info-value failed">{{ comparison.execution1.failedCount }}</span>
                  </div>
                  <div class="info-row" v-if="comparison.execution1.duration">
                    <span class="info-label">Duration</span>
                    <span class="info-value">{{ formatDuration(comparison.execution1.duration) }}</span>
                  </div>
                </div>
              </div>

              <div class="comparison-column">
                <h3 class="column-title">Execution 2</h3>
                <div class="execution-info">
                  <div class="info-row">
                    <span class="info-label">Suite Name</span>
                    <span class="info-value">{{ comparison.execution2.suiteName }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Timestamp</span>
                    <span class="info-value">{{ formatDateTime(comparison.execution2.timestamp) }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Score</span>
                    <span class="info-value" :class="getScoreClass(comparison.execution2.score)">
                      {{ comparison.execution2.score }}%
                    </span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Tests</span>
                    <span class="info-value">{{ comparison.execution2.testCount }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Passed</span>
                    <span class="info-value passed">{{ comparison.execution2.passedCount }}</span>
                  </div>
                  <div class="info-row">
                    <span class="info-label">Failed</span>
                    <span class="info-value failed">{{ comparison.execution2.failedCount }}</span>
                  </div>
                  <div class="info-row" v-if="comparison.execution2.duration">
                    <span class="info-label">Duration</span>
                    <span class="info-value">{{ formatDuration(comparison.execution2.duration) }}</span>
                  </div>
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
import { GitCompare, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  comparison: any | null;
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

const formatDiff = (value: number): string => {
  if (value > 0) return `+${value}`;
  if (value < 0) return `${value}`;
  return '0';
};

const getDiffClass = (value: number): string => {
  if (value > 0) return 'diff-positive';
  if (value < 0) return 'diff-negative';
  return 'diff-neutral';
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
  max-width: 1000px;
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

.comparison-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 16px;
  margin-bottom: 32px;
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.summary-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.summary-value {
  font-size: 1.25rem;
  font-weight: 700;
}

.diff-positive {
  color: #22c55e;
}

.diff-negative {
  color: #fc8181;
}

.diff-neutral {
  color: #a0aec0;
}

.comparison-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px;
}

.comparison-column {
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
}

.column-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.execution-info {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.info-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.info-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.info-value {
  font-size: 0.9rem;
  color: #ffffff;
  font-weight: 600;
}

.info-value.passed {
  color: #22c55e;
}

.info-value.failed {
  color: #fc8181;
}

.score-high {
  color: #22c55e;
}

.score-medium {
  color: #fbbf24;
}

.score-low {
  color: #fc8181;
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

@media (max-width: 768px) {
  .comparison-grid {
    grid-template-columns: 1fr;
  }
}
</style>

