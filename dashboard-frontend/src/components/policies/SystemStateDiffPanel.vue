<template>
  <div class="system-state-diff-panel">
    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Comparing with system state...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
      <button @click="loadComparison" class="btn-retry">Retry</button>
    </div>

    <div v-else-if="comparison" class="comparison-content">
      <!-- Compliance Score -->
      <div class="compliance-score">
        <div class="score-circle" :class="scoreClass">
          <div class="score-value">{{ comparison.compliance.compliancePercentage }}%</div>
          <div class="score-label">Compliant</div>
        </div>
        <div class="score-details">
          <div class="detail-item">
            <span class="detail-label">Status:</span>
            <span :class="['detail-value', comparison.compliance.isCompliant ? 'compliant' : 'non-compliant']">
              {{ comparison.compliance.isCompliant ? 'Compliant' : 'Non-Compliant' }}
            </span>
          </div>
          <div class="detail-item">
            <span class="detail-label">Enforced:</span>
            <span :class="['detail-value', comparison.actual.enforced ? 'yes' : 'no']">
              {{ comparison.actual.enforced ? 'Yes' : 'No' }}
            </span>
          </div>
          <div v-if="comparison.actual.enforcementLocation" class="detail-item">
            <span class="detail-label">Location:</span>
            <span class="detail-value">{{ comparison.actual.enforcementLocation }}</span>
          </div>
        </div>
      </div>

      <!-- Expected vs Actual -->
      <div class="comparison-sections">
        <div class="comparison-section">
          <h4>Expected State</h4>
          <div class="state-details">
            <div v-if="comparison.expected.rules.length > 0" class="detail-group">
              <span class="detail-label">Rules:</span>
              <span class="detail-value">{{ comparison.expected.rules.length }}</span>
            </div>
            <div v-if="comparison.expected.conditions.length > 0" class="detail-group">
              <span class="detail-label">Conditions:</span>
              <span class="detail-value">{{ comparison.expected.conditions.length }}</span>
            </div>
            <div class="detail-group">
              <span class="detail-label">Effect:</span>
              <span class="detail-value">{{ comparison.expected.effect }}</span>
            </div>
          </div>
        </div>

        <div class="comparison-section">
          <h4>Actual State</h4>
          <div class="state-details">
            <div v-if="comparison.actual.rules" class="detail-group">
              <span class="detail-label">Rules:</span>
              <span class="detail-value">{{ comparison.actual.rules.length }}</span>
            </div>
            <div v-else class="detail-group">
              <span class="detail-label">Rules:</span>
              <span class="detail-value missing">Not enforced</span>
            </div>
            <div v-if="comparison.actual.conditions" class="detail-group">
              <span class="detail-label">Conditions:</span>
              <span class="detail-value">{{ comparison.actual.conditions.length }}</span>
            </div>
            <div v-else-if="comparison.expected.conditions.length > 0" class="detail-group">
              <span class="detail-label">Conditions:</span>
              <span class="detail-value missing">Not enforced</span>
            </div>
            <div class="detail-group">
              <span class="detail-label">Effect:</span>
              <span class="detail-value" :class="effectMatch ? '' : 'mismatch'">
                {{ comparison.actual.effect || 'Not set' }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Gaps -->
      <div v-if="comparison.gaps.length > 0" class="gaps-section">
        <h4>Enforcement Gaps</h4>
        <div class="gaps-list">
          <div
            v-for="(gap, index) in comparison.gaps"
            :key="index"
            class="gap-item"
            :class="`severity-${gap.severity}`"
          >
            <div class="gap-header">
              <div class="gap-severity-badge" :class="`badge-${gap.severity}`">
                {{ gap.severity.toUpperCase() }}
              </div>
              <h5 class="gap-title">{{ gap.description }}</h5>
            </div>
            <div class="gap-details">
              <div v-if="gap.location" class="gap-location">
                <span class="label">Location:</span>
                <span class="value">{{ gap.location }}</span>
              </div>
              <div class="gap-remediation">
                <span class="label">Remediation Steps:</span>
                <ol class="remediation-steps">
                  <li v-for="step in gap.remediation" :key="step.order">
                    <strong>{{ step.action }}:</strong> {{ step.description }}
                    <div v-if="step.verification" class="verification">
                      Verify: {{ step.verification }}
                    </div>
                  </li>
                </ol>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-else class="no-gaps">
        <CheckCircle2 class="success-icon" />
        <p>No gaps detected. Policy is fully compliant.</p>
      </div>
    </div>

    <div v-else class="empty-state">
      <Shield class="empty-icon" />
      <h3>System State Comparison</h3>
      <p>Click "Compare with System State" to analyze compliance</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { Shield, AlertTriangle, CheckCircle2 } from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  policyId: string;
}

const props = defineProps<Props>();

interface EnforcementGap {
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  expected: any;
  actual: any;
  location?: string;
  remediation: Array<{
    order: number;
    action: string;
    description: string;
    expectedOutcome: string;
    verification?: string;
  }>;
}

interface SystemStateComparison {
  policyId: string;
  policyName: string;
  expected: {
    rules: any[];
    conditions: any[];
    effect: 'allow' | 'deny';
  };
  actual: {
    enforced: boolean;
    enforcementLocation?: string;
    rules?: any[];
    conditions?: any[];
    effect?: 'allow' | 'deny';
  };
  gaps: EnforcementGap[];
  compliance: {
    isCompliant: boolean;
    compliancePercentage: number;
    missingRules: any[];
    missingConditions: any[];
  };
}

const comparison = ref<SystemStateComparison | null>(null);
const loading = ref(false);
const error = ref<string>('');

const scoreClass = computed(() => {
  if (!comparison.value) return '';
  const score = comparison.value.compliance.compliancePercentage;
  if (score === 100) return 'score-perfect';
  if (score >= 80) return 'score-good';
  if (score >= 50) return 'score-warning';
  return 'score-critical';
});

const effectMatch = computed(() => {
  if (!comparison.value) return true;
  return comparison.value.expected.effect === comparison.value.actual.effect;
});

const loadComparison = async () => {
  loading.value = true;
  error.value = '';

  try {
    const response = await axios.get(
      `/api/policies/${props.policyId}/system-state-comparison`
    );
    comparison.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load comparison';
    comparison.value = null;
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadComparison();
});
</script>

<style scoped>
.system-state-diff-panel {
  display: flex;
  flex-direction: column;
  height: 100%;
  padding: var(--spacing-md);
}

.comparison-content {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.compliance-score {
  display: flex;
  align-items: center;
  gap: var(--spacing-xl);
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.score-circle {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  border: 4px solid;
  font-weight: 600;
}

.score-circle.score-perfect {
  border-color: var(--color-success);
  background: rgba(var(--color-success-rgb), 0.1);
}

.score-circle.score-good {
  border-color: var(--color-success);
  background: rgba(var(--color-success-rgb), 0.1);
}

.score-circle.score-warning {
  border-color: var(--color-warning);
  background: rgba(var(--color-warning-rgb), 0.1);
}

.score-circle.score-critical {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.1);
}

.score-value {
  font-size: var(--font-size-2xl);
  font-weight: 700;
  line-height: 1;
}

.score-label {
  font-size: var(--font-size-xs);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-top: var(--spacing-xs);
}

.score-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  flex: 1;
}

.detail-item {
  display: flex;
  gap: var(--spacing-sm);
}

.detail-label {
  font-weight: 500;
  color: var(--color-text-secondary);
  min-width: 80px;
}

.detail-value {
  font-weight: 600;
}

.detail-value.compliant {
  color: var(--color-success);
}

.detail-value.non-compliant {
  color: var(--color-error);
}

.detail-value.yes {
  color: var(--color-success);
}

.detail-value.no {
  color: var(--color-error);
}

.detail-value.missing {
  color: var(--color-error);
}

.detail-value.mismatch {
  color: var(--color-warning);
}

.comparison-sections {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.comparison-section {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.comparison-section h4 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-md);
  font-weight: 600;
  color: var(--color-text-primary);
}

.state-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.detail-group {
  display: flex;
  gap: var(--spacing-sm);
}

.gaps-section {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.gaps-section h4 {
  margin: 0;
  font-size: var(--font-size-md);
  font-weight: 600;
}

.gaps-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.gap-item {
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  border-left: 4px solid;
  background: var(--color-bg-secondary);
}

.gap-item.severity-critical {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.1);
}

.gap-item.severity-high {
  border-color: var(--color-error);
  background: rgba(var(--color-error-rgb), 0.05);
}

.gap-item.severity-medium {
  border-color: var(--color-warning);
  background: rgba(var(--color-warning-rgb), 0.05);
}

.gap-item.severity-low {
  border-color: var(--color-text-secondary);
  background: var(--color-bg-secondary);
}

.gap-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-sm);
}

.gap-severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.badge-critical,
.badge-high {
  background: var(--color-error);
  color: white;
}

.badge-medium {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.badge-low {
  background: var(--color-text-secondary);
  color: white;
}

.gap-title {
  margin: 0;
  font-size: var(--font-size-sm);
  font-weight: 600;
  flex: 1;
}

.gap-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  margin-top: var(--spacing-sm);
}

.gap-location,
.gap-remediation {
  font-size: var(--font-size-sm);
}

.gap-location .label,
.gap-remediation .label {
  font-weight: 500;
  color: var(--color-text-secondary);
  margin-right: var(--spacing-xs);
}

.remediation-steps {
  margin: var(--spacing-sm) 0 0 var(--spacing-md);
  padding-left: var(--spacing-md);
}

.remediation-steps li {
  margin-bottom: var(--spacing-xs);
  line-height: 1.6;
}

.verification {
  margin-top: var(--spacing-xs);
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  font-style: italic;
}

.no-gaps {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--color-success);
}

.success-icon {
  width: 48px;
  height: 48px;
  color: var(--color-success);
  margin-bottom: var(--spacing-md);
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  min-height: 400px;
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon,
.empty-icon {
  width: 48px;
  height: 48px;
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}

.btn-retry {
  margin-top: var(--spacing-md);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-primary);
  color: white;
  border: none;
  border-radius: var(--border-radius-sm);
  cursor: pointer;
  font-weight: 500;
}
</style>
