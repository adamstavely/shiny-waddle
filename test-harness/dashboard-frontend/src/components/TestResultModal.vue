<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen && result" class="modal-overlay" @click="close">
        <div class="modal-content test-result-viewer" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <Globe class="modal-title-icon" />
              <h2>{{ result.testName }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <!-- Test Summary -->
            <div class="summary-section">
              <div class="summary-cards">
                <div class="summary-card">
                  <div class="summary-card-label">Status</div>
                  <div class="summary-card-value" :class="result.passed ? 'passed' : 'failed'">
                    {{ result.passed ? 'Passed' : 'Failed' }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-card-label">Test Type</div>
                  <div class="summary-card-value">{{ formatTestType(result.distributedTestType) }}</div>
                </div>
                <div class="summary-card" v-if="result.performanceMetrics">
                  <div class="summary-card-label">Avg Latency</div>
                  <div class="summary-card-value">{{ result.performanceMetrics.averageLatency }}ms</div>
                </div>
                <div class="summary-card" v-if="result.regionResults">
                  <div class="summary-card-label">Regions Tested</div>
                  <div class="summary-card-value">{{ result.regionResults.length }}</div>
                </div>
              </div>
            </div>

            <!-- Consistency Check -->
            <div v-if="result.consistencyCheck" class="section">
              <h3>Consistency Check</h3>
              <div class="consistency-status" :class="result.consistencyCheck.consistent ? 'consistent' : 'inconsistent'">
                <CheckCircle2 v-if="result.consistencyCheck.consistent" class="status-icon" />
                <X v-else class="status-icon" />
                <span>{{ result.consistencyCheck.consistent ? 'All regions are consistent' : 'Inconsistencies detected' }}</span>
              </div>
              <div v-if="result.consistencyCheck.inconsistencies && result.consistencyCheck.inconsistencies.length > 0" class="inconsistencies-list">
                <div
                  v-for="(inc, index) in result.consistencyCheck.inconsistencies"
                  :key="index"
                  class="inconsistency-item"
                >
                  <AlertTriangle class="alert-icon" />
                  <div class="inconsistency-details">
                    <div class="inconsistency-regions">{{ inc.region1 }} ↔ {{ inc.region2 }}</div>
                    <div class="inconsistency-difference">{{ inc.difference }}</div>
                    <div class="inconsistency-severity" :class="`severity-${inc.severity}`">
                      {{ inc.severity }}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Synchronization Check -->
            <div v-if="result.synchronizationCheck" class="section">
              <h3>Synchronization Check</h3>
              <div class="sync-status" :class="result.synchronizationCheck.synchronized ? 'synchronized' : 'not-synchronized'">
                <CheckCircle2 v-if="result.synchronizationCheck.synchronized" class="status-icon" />
                <X v-else class="status-icon" />
                <span>{{ result.synchronizationCheck.synchronized ? 'All regions synchronized' : 'Regions out of sync' }}</span>
              </div>
              <div v-if="result.synchronizationCheck.syncTime" class="sync-time">
                Sync Time: {{ result.synchronizationCheck.syncTime }}ms
              </div>
              <div v-if="result.synchronizationCheck.regionsOutOfSync && result.synchronizationCheck.regionsOutOfSync.length > 0" class="regions-out-of-sync">
                <div class="label">Regions Out of Sync:</div>
                <div class="region-tags">
                  <span v-for="region in result.synchronizationCheck.regionsOutOfSync" :key="region" class="region-tag">
                    {{ region }}
                  </span>
                </div>
              </div>
            </div>

            <!-- Performance Metrics -->
            <div v-if="result.performanceMetrics" class="section">
              <h3>Performance Metrics</h3>
              <div class="metrics-grid">
                <div class="metric-item">
                  <div class="metric-label">Total Time</div>
                  <div class="metric-value">{{ result.performanceMetrics.totalTime }}ms</div>
                </div>
                <div class="metric-item">
                  <div class="metric-label">Average Latency</div>
                  <div class="metric-value">{{ result.performanceMetrics.averageLatency }}ms</div>
                </div>
                <div class="metric-item">
                  <div class="metric-label">Fastest Region</div>
                  <div class="metric-value">{{ result.performanceMetrics.fastestRegion }}</div>
                </div>
                <div class="metric-item">
                  <div class="metric-label">Slowest Region</div>
                  <div class="metric-value">{{ result.performanceMetrics.slowestRegion }}</div>
                </div>
              </div>
            </div>

            <!-- Region Results -->
            <div v-if="result.regionResults && result.regionResults.length > 0" class="section">
              <h3>Region Results</h3>
              <div class="region-results-list">
                <div
                  v-for="region in result.regionResults"
                  :key="region.regionId"
                  class="region-result-card"
                  :class="{ 'allowed': region.allowed, 'denied': !region.allowed }"
                >
                  <div class="region-result-header">
                    <div>
                      <div class="region-result-name">{{ region.regionName }}</div>
                      <div class="region-result-id">{{ region.regionId }}</div>
                    </div>
                    <div class="region-result-status">
                      <CheckCircle2 v-if="region.allowed" class="status-icon passed" />
                      <X v-else class="status-icon failed" />
                      <span>{{ region.allowed ? 'Allowed' : 'Denied' }}</span>
                    </div>
                  </div>
                  <div class="region-result-details">
                    <div class="detail-row">
                      <span class="detail-label">Latency:</span>
                      <span class="detail-value">{{ region.latency }}ms</span>
                    </div>
                    <div class="detail-row">
                      <span class="detail-label">Timestamp:</span>
                      <span class="detail-value">{{ formatDate(region.timestamp) }}</span>
                    </div>
                    <div v-if="region.error" class="detail-row error">
                      <span class="detail-label">Error:</span>
                      <span class="detail-value">{{ region.error }}</span>
                    </div>
                    <div v-if="region.decision" class="decision-preview">
                      <div class="detail-label">Decision:</div>
                      <pre class="decision-json">{{ JSON.stringify(region.decision, null, 2) }}</pre>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Error Details -->
            <div v-if="result.error" class="section error-section">
              <h3>Error</h3>
              <div class="error-message">{{ result.error }}</div>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { Teleport } from 'vue';
import { Globe, X, CheckCircle2, AlertTriangle } from 'lucide-vue-next';

const props = defineProps<{
  isOpen: boolean;
  result: any;
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
}>();

const close = () => {
  emit('update:isOpen', false);
};

const formatTestType = (type: string): string => {
  return type
    .split('-')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
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

.test-result-viewer {
  max-width: 1000px;
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

.summary-card-value.passed {
  color: #22c55e;
}

.summary-card-value.failed {
  color: #fc8181;
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

.consistency-status,
.sync-status {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  border-radius: 8px;
  margin-bottom: 16px;
}

.consistency-status.consistent,
.sync-status.synchronized {
  background: rgba(34, 197, 94, 0.1);
  border: 1px solid rgba(34, 197, 94, 0.3);
  color: #22c55e;
}

.consistency-status.inconsistent,
.sync-status.not-synchronized {
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  color: #fc8181;
}

.status-icon {
  width: 20px;
  height: 20px;
}

.status-icon.passed {
  color: #22c55e;
}

.status-icon.failed {
  color: #fc8181;
}

.inconsistencies-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.inconsistency-item {
  display: flex;
  gap: 12px;
  padding: 12px;
  background: rgba(251, 191, 36, 0.1);
  border: 1px solid rgba(251, 191, 36, 0.3);
  border-radius: 8px;
}

.alert-icon {
  width: 20px;
  height: 20px;
  color: #fbbf24;
  flex-shrink: 0;
}

.inconsistency-details {
  flex: 1;
}

.inconsistency-regions {
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 4px;
}

.inconsistency-difference {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 4px;
}

.inconsistency-severity {
  display: inline-block;
  padding: 4px 8px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.severity-critical {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.severity-high {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-medium {
  background: rgba(79, 172, 254, 0.2);
  color: #4facfe;
}

.severity-low {
  background: rgba(160, 174, 192, 0.2);
  color: #a0aec0;
}

.sync-time {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 12px;
}

.regions-out-of-sync {
  margin-top: 12px;
}

.regions-out-of-sync .label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.region-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.region-tag {
  padding: 4px 12px;
  background: rgba(252, 129, 129, 0.1);
  border: 1px solid rgba(252, 129, 129, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #fc8181;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.metric-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.8);
  border-radius: 8px;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.metric-value {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
}

.region-results-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.region-result-card {
  padding: 16px;
  background: rgba(15, 20, 25, 0.8);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.region-result-card.allowed {
  border-color: rgba(34, 197, 94, 0.3);
}

.region-result-card.denied {
  border-color: rgba(252, 129, 129, 0.3);
}

.region-result-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 12px;
}

.region-result-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 4px;
}

.region-result-id {
  font-size: 0.875rem;
  color: #718096;
}

.region-result-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.875rem;
  font-weight: 500;
}

.region-result-details {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.detail-row {
  display: flex;
  gap: 8px;
  font-size: 0.875rem;
}

.detail-row.error {
  color: #fc8181;
}

.detail-label {
  color: #718096;
  font-weight: 500;
  min-width: 100px;
}

.detail-value {
  color: #ffffff;
}

.decision-preview {
  margin-top: 8px;
}

.decision-json {
  margin: 8px 0 0 0;
  padding: 12px;
  background: rgba(0, 0, 0, 0.3);
  border-radius: 6px;
  font-size: 0.75rem;
  color: #a0aec0;
  overflow-x: auto;
}

.error-section {
  background: rgba(252, 129, 129, 0.1);
  border-color: rgba(252, 129, 129, 0.3);
}

.error-message {
  color: #fc8181;
  font-size: 0.9rem;
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

