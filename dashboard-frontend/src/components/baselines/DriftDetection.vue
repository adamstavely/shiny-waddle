<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="visible" class="modal-overlay" @click="close">
        <div class="modal-content drift-modal" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <AlertTriangle class="modal-title-icon" />
              <div>
                <h2>Drift Detection</h2>
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
              <p>Detecting drift...</p>
            </div>

            <div v-else-if="error" class="error-state">
              <AlertTriangle class="error-icon" />
              <p>{{ error }}</p>
              <button @click="detect" class="btn-retry">Retry</button>
            </div>

            <div v-else-if="driftResult">
              <!-- Overall Status -->
              <div class="status-banner" :class="driftResult.hasDrift ? 'has-drift' : 'no-drift'">
                <div class="status-content">
                  <AlertTriangle v-if="driftResult.hasDrift" class="status-icon" />
                  <CheckCircle v-else class="status-icon" />
                  <div>
                    <div class="status-title">
                      {{ driftResult.hasDrift ? 'Drift Detected' : 'No Drift Detected' }}
                    </div>
                    <div class="status-subtitle">
                      {{ driftResult.hasDrift 
                        ? 'Configuration has diverged from baseline' 
                        : 'Configuration matches baseline' }}
                    </div>
                  </div>
                </div>
              </div>

              <!-- Scores Grid -->
              <div class="scores-grid">
                <div class="score-card">
                  <div class="score-label">Drift Score</div>
                  <div class="score-value" :class="getDriftClass(driftResult.driftScore)">
                    {{ driftResult.driftScore || 0 }}
                  </div>
                  <div class="score-description">Higher = more drift</div>
                </div>
                <div class="score-card">
                  <div class="score-label">Compliance Score</div>
                  <div class="score-value" :class="getComplianceClass(driftResult.complianceScore)">
                    {{ driftResult.complianceScore || 0 }}%
                  </div>
                  <div class="score-description">Higher = more compliant</div>
                </div>
              </div>

              <!-- HIPAA Compliance Breakdown -->
              <div v-if="driftResult.hipaaCompliance" class="hipaa-section">
                <h3 class="section-title">
                  <Shield class="section-icon" />
                  HIPAA Compliance Breakdown
                </h3>
                <div class="hipaa-scores">
                  <div class="hipaa-score-card">
                    <div class="hipaa-score-label">Security Rule</div>
                    <div class="hipaa-score-value" :class="getComplianceClass(driftResult.hipaaCompliance.securityRuleScore)">
                      {{ driftResult.hipaaCompliance.securityRuleScore }}%
                    </div>
                  </div>
                  <div class="hipaa-score-card">
                    <div class="hipaa-score-label">Privacy Rule</div>
                    <div class="hipaa-score-value" :class="getComplianceClass(driftResult.hipaaCompliance.privacyRuleScore)">
                      {{ driftResult.hipaaCompliance.privacyRuleScore }}%
                    </div>
                  </div>
                  <div class="hipaa-score-card">
                    <div class="hipaa-score-label">Breach Notification</div>
                    <div class="hipaa-score-value" :class="getComplianceClass(driftResult.hipaaCompliance.breachNotificationScore)">
                      {{ driftResult.hipaaCompliance.breachNotificationScore }}%
                    </div>
                  </div>
                  <div class="hipaa-score-card overall">
                    <div class="hipaa-score-label">Overall HIPAA</div>
                    <div class="hipaa-score-value" :class="getComplianceClass(driftResult.hipaaCompliance.overallScore)">
                      {{ driftResult.hipaaCompliance.overallScore }}%
                    </div>
                  </div>
                </div>

                <!-- HIPAA Violations -->
                <div v-if="driftResult.hipaaCompliance.violations && driftResult.hipaaCompliance.violations.length > 0" class="violations-section">
                  <h4 class="violations-title">HIPAA Violations</h4>
                  <div class="violations-list">
                    <div
                      v-for="(violation, index) in driftResult.hipaaCompliance.violations"
                      :key="index"
                      class="violation-item"
                      :class="`severity-${violation.severity}`"
                    >
                      <div class="violation-header">
                        <Shield class="violation-icon" />
                        <div class="violation-rule">{{ violation.rule }}</div>
                        <div class="violation-severity-badge" :class="`severity-${violation.severity}`">
                          {{ violation.severity }}
                        </div>
                      </div>
                      <div class="violation-requirement">{{ violation.requirement }}</div>
                      <div class="violation-description">{{ violation.description }}</div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Recommendations -->
              <div v-if="driftResult.recommendations && driftResult.recommendations.length > 0" class="recommendations-section">
                <h3 class="section-title">
                  <Lightbulb class="section-icon" />
                  Recommendations
                </h3>
                <div class="recommendations-list">
                  <div
                    v-for="(rec, index) in driftResult.recommendations"
                    :key="index"
                    class="recommendation-item"
                    :class="`priority-${rec.priority}`"
                  >
                    <div class="recommendation-header">
                      <div class="recommendation-priority-badge" :class="`priority-${rec.priority}`">
                        {{ rec.priority }}
                      </div>
                      <div class="recommendation-action">{{ rec.action }}</div>
                    </div>
                    <div class="recommendation-description">{{ rec.description }}</div>
                  </div>
                </div>
              </div>

              <!-- Drifts List -->
              <div v-if="driftResult.drifts && driftResult.drifts.length > 0" class="drifts-section">
                <h3 class="section-title">Configuration Drifts</h3>
                <div class="drifts-list">
                  <div
                    v-for="(drift, index) in driftResult.drifts"
                    :key="index"
                    class="drift-item"
                    :class="`severity-${drift.severity}`"
                  >
                    <div class="drift-header">
                      <div class="drift-type-badge" :class="`type-${drift.type}`">
                        {{ getTypeLabel(drift.type) }}
                      </div>
                      <div class="drift-severity-badge" :class="`severity-${drift.severity}`">
                        {{ drift.severity }}
                      </div>
                    </div>
                    <div class="drift-path">
                      <code>{{ drift.path }}</code>
                    </div>
                    <div class="drift-description">{{ drift.description }}</div>
                    <div v-if="drift.hipaaImpact" class="drift-hipaa">
                      <Shield class="hipaa-icon" />
                      <div>
                        <div class="hipaa-rule">{{ drift.hipaaImpact.rule }}</div>
                        <div class="hipaa-requirement">{{ drift.hipaaImpact.requirement }}</div>
                      </div>
                    </div>
                  </div>
                </div>
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
  AlertTriangle,
  X,
  Shield,
  CheckCircle,
  Lightbulb
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
const driftResult = ref<any>(null);

const close = () => {
  emit('close');
};

const detect = async () => {
  if (!props.baselineId) return;

  loading.value = true;
  error.value = null;
  driftResult.value = null;

  try {
    const endpoint = `/api/v1/${props.platform}/baselines/${props.baselineId}/detect-drift`;
    const response = await axios.post(endpoint, {
      currentConfig: props.currentConfig || {}
    });
    driftResult.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to detect drift';
    console.error('Error detecting drift:', err);
  } finally {
    loading.value = false;
  }
};

watch(() => props.visible, (newVal) => {
  if (newVal) {
    detect();
  } else {
    driftResult.value = null;
    error.value = null;
  }
});

const getDriftClass = (score: number | undefined): string => {
  if (!score) return 'drift-low';
  if (score >= 70) return 'drift-critical';
  if (score >= 50) return 'drift-high';
  if (score >= 30) return 'drift-medium';
  return 'drift-low';
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

.drift-modal {
  width: 100%;
  max-width: 1000px;
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

.status-banner {
  padding: var(--spacing-lg);
  border-radius: var(--border-radius-lg);
  margin-bottom: var(--spacing-xl);
}

.status-banner.has-drift {
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
}

.status-banner.no-drift {
  background: var(--color-success-bg);
  border: var(--border-width-thin) solid var(--color-success);
}

.status-content {
  display: flex;
  align-items: center;
  gap: var(--spacing-md);
}

.status-icon {
  width: 32px;
  height: 32px;
  flex-shrink: 0;
}

.status-banner.has-drift .status-icon {
  color: var(--color-error);
}

.status-banner.no-drift .status-icon {
  color: var(--color-success);
}

.status-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xs);
}

.status-subtitle {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.scores-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-xl);
}

.score-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  text-align: center;
}

.score-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.score-value {
  font-size: var(--font-size-3xl);
  font-weight: var(--font-weight-bold);
  margin-bottom: var(--spacing-xs);
}

.score-value.drift-critical,
.score-value.compliance-low {
  color: var(--color-error);
}

.score-value.drift-high,
.score-value.compliance-medium {
  color: #ff9800;
}

.score-value.drift-medium,
.score-value.compliance-high {
  color: var(--color-primary);
}

.score-value.drift-low {
  color: var(--color-success);
}

.score-description {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.hipaa-section,
.recommendations-section,
.drifts-section {
  margin-top: var(--spacing-xl);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.section-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
}

.hipaa-scores {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--spacing-md);
  margin-bottom: var(--spacing-lg);
}

.hipaa-score-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-md);
  text-align: center;
}

.hipaa-score-card.overall {
  border-width: 2px;
  border-color: var(--color-primary);
  background: var(--color-primary-bg);
}

.hipaa-score-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.hipaa-score-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
}

.hipaa-score-value.compliance-high {
  color: var(--color-success);
}

.hipaa-score-value.compliance-medium {
  color: #ff9800;
}

.hipaa-score-value.compliance-low {
  color: var(--color-error);
}

.violations-section {
  margin-top: var(--spacing-lg);
}

.violations-title {
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.violations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.violation-item {
  background: var(--color-error-bg);
  border: var(--border-width-thin) solid var(--color-error);
  border-left-width: 4px;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
}

.violation-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.violation-icon {
  width: 18px;
  height: 18px;
  color: var(--color-error);
}

.violation-rule {
  flex: 1;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.violation-severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.violation-severity-badge.severity-critical {
  background: var(--color-error);
  color: white;
}

.violation-severity-badge.severity-high {
  background: #ff9800;
  color: white;
}

.violation-requirement {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-error);
  margin-bottom: var(--spacing-xs);
}

.violation-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.recommendations-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.recommendation-item {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left-width: 4px;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
}

.recommendation-item.priority-critical {
  border-left-color: var(--color-error);
}

.recommendation-item.priority-high {
  border-left-color: #ff9800;
}

.recommendation-item.priority-medium {
  border-left-color: var(--color-primary);
}

.recommendation-item.priority-low {
  border-left-color: var(--color-text-secondary);
}

.recommendation-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.recommendation-priority-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.recommendation-priority-badge.priority-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.recommendation-priority-badge.priority-high {
  background: #fff3cd;
  color: #856404;
}

.recommendation-priority-badge.priority-medium {
  background: #e3f2fd;
  color: #1976d2;
}

.recommendation-priority-badge.priority-low {
  background: var(--border-color-muted);
  color: var(--color-text-secondary);
}

.recommendation-action {
  flex: 1;
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.recommendation-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-top: var(--spacing-xs);
}

.drifts-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.drift-item {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-left-width: 4px;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
}

.drift-item.severity-critical {
  border-left-color: var(--color-error);
}

.drift-item.severity-high {
  border-left-color: #ff9800;
}

.drift-item.severity-medium {
  border-left-color: var(--color-primary);
}

.drift-item.severity-low {
  border-left-color: var(--color-text-secondary);
}

.drift-header {
  display: flex;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
  flex-wrap: wrap;
}

.drift-type-badge,
.drift-severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-xs);
  font-weight: var(--font-weight-semibold);
  text-transform: capitalize;
}

.drift-type-badge.type-encryption_gap,
.drift-type-badge.type-access_control_issue,
.drift-type-badge.type-retention_policy_violation {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.drift-severity-badge.severity-critical {
  background: var(--color-error-bg);
  color: var(--color-error);
}

.drift-severity-badge.severity-high {
  background: #fff3cd;
  color: #856404;
}

.drift-path {
  margin: var(--spacing-sm) 0;
}

.drift-path code {
  background: var(--color-bg-overlay-dark);
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: var(--font-size-sm);
  color: var(--color-primary);
}

.drift-description {
  color: var(--color-text-primary);
  margin: var(--spacing-sm) 0;
  line-height: 1.5;
}

.drift-hipaa {
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
