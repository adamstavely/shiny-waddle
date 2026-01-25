<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="visible" class="modal-overlay" @click="close">
        <div class="modal-content comparison-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <GitCompare class="modal-title-icon" />
              <div>
                <h2>Baseline Comparison</h2>
                <p class="modal-subtitle">{{ baselineName }}</p>
              </div>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <div v-if="loading" class="loading-state">
              <div class="loading-spinner"></div>
              <p>Comparing configurations...</p>
            </div>

            <div v-else-if="error" class="error-state">
              <AlertTriangle class="error-icon" />
              <p>{{ error }}</p>
              <button @click="compare" class="btn-retry">Retry</button>
            </div>

            <div v-else-if="comparisonResult">
              <!-- Summary Cards -->
              <div class="summary-cards">
                <div class="summary-card">
                  <div class="summary-label">Risk Score</div>
                  <div class="summary-value" :class="getRiskClass(comparisonResult.riskScore)">
                    {{ comparisonResult.riskScore || 0 }}
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-label">Compliance Score</div>
                  <div class="summary-value" :class="getComplianceClass(comparisonResult.complianceScore)">
                    {{ comparisonResult.complianceScore || 0 }}%
                  </div>
                </div>
                <div class="summary-card">
                  <div class="summary-label">Differences</div>
                  <div class="summary-value">
                    {{ comparisonResult.differences?.length || 0 }}
                  </div>
                </div>
              </div>

              <!-- Differences List -->
              <div v-if="comparisonResult.differences && comparisonResult.differences.length > 0" class="differences-section">
                <h3 class="section-title">Configuration Differences</h3>
                <div class="differences-list">
                  <div
                    v-for="(diff, index) in comparisonResult.differences"
                    :key="index"
                    class="difference-item"
                    :class="`severity-${diff.severity}`"
                  >
                    <div class="difference-header">
                      <div class="difference-type-badge" :class="`type-${diff.type}`">
                        {{ getTypeLabel(diff.type) }}
                      </div>
                      <div class="difference-severity-badge" :class="`severity-${diff.severity}`">
                        {{ diff.severity }}
                      </div>
                    </div>
                    <div class="difference-path">
                      <code>{{ diff.path }}</code>
                    </div>
                    <div class="difference-description">
                      {{ diff.description }}
                    </div>
                    <div v-if="diff.hipaaImpact" class="difference-hipaa">
                      <Shield class="hipaa-icon" />
                      <div>
                        <div class="hipaa-rule">{{ diff.hipaaImpact.rule }}</div>
                        <div class="hipaa-requirement">{{ diff.hipaaImpact.requirement }}</div>
                      </div>
                    </div>
                    <div v-if="diff.baselineValue !== undefined || diff.currentValue !== undefined" class="difference-values">
                      <div v-if="diff.baselineValue !== undefined" class="value-item">
                        <span class="value-label">Baseline:</span>
                        <code class="value-content">{{ formatValue(diff.baselineValue) }}</code>
                      </div>
                      <div v-if="diff.currentValue !== undefined" class="value-item">
                        <span class="value-label">Current:</span>
                        <code class="value-content">{{ formatValue(diff.currentValue) }}</code>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div v-else class="no-differences">
                <CheckCircle class="no-diff-icon" />
                <p>No differences found. Current configuration matches the baseline.</p>
              </div>
            </div>
          </div>

          <div class="modal-footer">
            <button @click="close" class="btn-secondary">Close</button>
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
  GitCompare,
  X,
  AlertTriangle,
  Shield,
  CheckCircle
} from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  visible: boolean;
  baselineId: string | null;
  baselineName: string;
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes' | 'servicenow';
  currentConfig?: Record<string, any>;
}

const props = defineProps<Props>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();

const loading = ref(false);
const error = ref<string | null>(null);
const comparisonResult = ref<any>(null);

const close = () => {
  emit('close');
};

const compare = async () => {
  if (!props.baselineId) return;

  loading.value = true;
  error.value = null;
  comparisonResult.value = null;

  try {
    const endpoint = `/api/v1/${props.platform}/baselines/${props.baselineId}/compare`;
    const response = await axios.post(endpoint, {
      currentConfig: props.currentConfig || {}
    });
    comparisonResult.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to compare baseline';
    console.error('Error comparing baseline:', err);
  } finally {
    loading.value = false;
  }
};

watch(() => props.visible, (newVal) => {
  if (newVal) {
    compare();
  } else {
    comparisonResult.value = null;
    error.value = null;
  }
});

const getRiskClass = (score: number | undefined): string => {
  if (!score) return 'risk-low';
  if (score >= 70) return 'risk-critical';
  if (score >= 50) return 'risk-high';
  if (score >= 30) return 'risk-medium';
  return 'risk-low';
};

const getComplianceClass = (score: number | undefined): string => {
  if (!score) return 'compliance-low';
  if (score >= 90) return 'compliance-high';
  if (score >= 70) return 'compliance-medium';
  return 'compliance-low';
};

const getTypeLabel = (type: string): string => {
  const labels: Record<string, string> = {
    'added': 'Added',
    'removed': 'Removed',
    'modified': 'Modified',
    'encryption_gap': 'Encryption Gap',
    'access_control_issue': 'Access Control Issue',
    'retention_policy_violation': 'Retention Violation'
  };
  return labels[type] || type;
};

const formatValue = (value: any): string => {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: var(--color-bg-overlay-dark);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: var(--z-index-modal);
  padding: var(--spacing-xl);
}

.comparison-modal {
  width: 100%;
  max-width: 900px;
  max-height: 90vh;
  display: flex;
  flex-direction: column;
}

.modal-content {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: var(--spacing-lg);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.modal-title-group {
  display: flex;
  align-items: flex-start;
  gap: var(--spacing-sm);
  flex: 1;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
  margin-top: 2px;
}

.modal-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.modal-subtitle {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.modal-close {
  padding: var(--spacing-sm);
  background: transparent;
  border: none;
  border-radius: var(--border-radius-md);
  cursor: pointer;
  color: var(--color-text-secondary);
  transition: var(--transition-all);
  display: flex;
  align-items: center;
  justify-content: center;
}

.modal-close:hover {
  background: var(--border-color-muted);
  color: var(--color-primary);
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: var(--spacing-lg);
  overflow-y: auto;
  flex: 1;
}

.loading-state,
.error-state {
  text-align: center;
  padding: var(--spacing-2xl);
}

.loading-spinner {
  width: 48px;
  height: 48px;
  border: 4px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto var(--spacing-lg);
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin: 0 auto var(--spacing-md);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-lg);
  background: var(--border-color-muted);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-primary);
  font-weight: var(--font-weight-medium);
  cursor: pointer;
  transition: var(--transition-all);
}

.summary-cards {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.summary-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  text-align: center;
}

.summary-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.summary-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.summary-value.risk-critical,
.summary-value.compliance-low {
  color: var(--color-error);
}

.summary-value.risk-high,
.summary-value.compliance-medium {
  color: #ff9800;
}

.summary-value.risk-medium,
.summary-value.compliance-high {
  color: var(--color-primary);
}

.summary-value.risk-low {
  color: var(--color-success);
}

.differences-section {
  margin-top: var(--spacing-xl);
}

.section-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.differences-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.difference-item {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left-width: 4px;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  transition: var(--transition-all);
}

.difference-item.severity-critical {
  border-left-color: var(--color-error);
}

.difference-item.severity-high {
  border-left-color: #ff9800;
}

.difference-item.severity-medium {
  border-left-color: var(--color-primary);
}

.difference-item.severity-low {
  border-left-color: var(--color-text-secondary);
}

.difference-header {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
  flex-wrap: wrap;
}

.difference-type-badge,
.difference-severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.difference-type-badge.type-added {
  background: var(--color-success-bg);
  color: var(--color-success);
}

.difference-type-badge.type-removed {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.difference-type-badge.type-modified {
  background: #fff3cd;
  color: #856404;
}

.difference-type-badge.type-encryption_gap,
.difference-type-badge.type-access_control_issue,
.difference-type-badge.type-retention_policy_violation {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.difference-severity-badge.severity-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.difference-severity-badge.severity-high {
  background: #fff3cd;
  color: #856404;
}

.difference-severity-badge.severity-medium {
  background: #e3f2fd;
  color: #1976d2;
}

.difference-severity-badge.severity-low {
  background: var(--border-color-muted);
  color: var(--color-text-secondary);
}

.difference-path {
  margin: var(--spacing-sm) 0;
}

.difference-path code {
  background: var(--color-bg-overlay-dark);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: var(--font-size-sm);
  color: var(--color-primary);
}

.difference-description {
  color: var(--color-text-primary);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.difference-hipaa {
  display: flex;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
  padding: var(--spacing-sm);
  background: var(--color-primary-bg);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--color-primary);
}

.hipaa-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.hipaa-rule {
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  color: var(--color-primary);
}

.hipaa-requirement {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin-top: 2px;
}

.difference-values {
  margin-top: var(--spacing-sm);
  padding-top: var(--spacing-sm);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.value-item {
  display: flex;
  gap: var(--spacing-sm);
  align-items: flex-start;
}

.value-label {
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-secondary);
  min-width: 80px;
}

.value-content {
  flex: 1;
  background: var(--color-bg-overlay-dark);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: var(--font-size-xs);
  color: var(--color-text-primary);
  white-space: pre-wrap;
  word-break: break-all;
}

.no-differences {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.no-diff-icon {
  width: 64px;
  height: 64px;
  color: var(--color-success);
  margin: 0 auto var(--spacing-md);
  opacity: 0.7;
}

.modal-footer {
  padding: var(--spacing-lg);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  justify-content: flex-end;
}

.btn-secondary {
  padding: var(--spacing-sm) var(--spacing-lg);
  background: transparent;
  border: var(--border-width-medium) solid var(--border-color-secondary);
  border-radius: var(--border-radius-lg);
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
  cursor: pointer;
  transition: var(--transition-all);
}

.btn-secondary:hover {
  background: var(--border-color-muted);
  border-color: var(--border-color-primary-active);
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
