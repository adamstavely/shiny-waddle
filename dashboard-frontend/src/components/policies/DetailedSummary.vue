<template>
  <div class="detailed-summary">
    <!-- Policy Changes -->
    <div class="section">
      <h3>Policy Changes</h3>
      <div class="policy-changes-list">
        <div
          v-for="change in summary.policyChanges"
          :key="change.policyId"
          class="policy-change-card"
        >
          <div class="change-header">
            <h4>{{ change.policyName }}</h4>
            <span class="change-type-badge" :class="`type-${change.changeType}`">
              {{ change.changeType }}
            </span>
          </div>
          <div class="change-details">
            <div v-if="change.changes.length > 0" class="changes-list">
              <strong>Changes:</strong>
              <ul>
                <li v-for="(c, index) in change.changes" :key="index">{{ c }}</li>
              </ul>
            </div>
            <div v-if="change.affectedResources.length > 0" class="affected-resources">
              <strong>Affected Resources:</strong> {{ change.affectedResources.join(', ') }}
            </div>
            <div v-if="change.affectedApplications.length > 0" class="affected-applications">
              <strong>Affected Applications:</strong> {{ change.affectedApplications.join(', ') }}
            </div>
            <div v-if="change.requiredActions.length > 0" class="required-actions">
              <strong>Required Actions:</strong>
              <ul>
                <li v-for="(action, index) in change.requiredActions" :key="index">{{ action }}</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Compliance Status -->
    <div class="section">
      <h3>Compliance Status</h3>
      <div class="compliance-status">
        <div class="overall-score">
          <div class="score-label">Overall Compliance Score</div>
          <div class="score-value" :class="getScoreClass(summary.complianceStatus.overallScore)">
            {{ summary.complianceStatus.overallScore }}%
          </div>
        </div>
        <div class="policy-scores">
          <h4>Policy Scores</h4>
          <div class="scores-list">
            <div
              v-for="policyScore in summary.complianceStatus.policyScores"
              :key="policyScore.policyId"
              class="score-item"
            >
              <span class="policy-name">{{ policyScore.policyName }}</span>
              <span class="score" :class="getScoreClass(policyScore.score)">
                {{ policyScore.score }}%
              </span>
              <span class="gaps-count" v-if="policyScore.gaps > 0">
                {{ policyScore.gaps }} gaps
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Gap Analysis -->
    <div class="section">
      <h3>Gap Analysis</h3>
      <div class="gap-analysis">
        <div class="gap-summary">
          <div class="summary-item">
            <span class="label">Total Gaps:</span>
            <span class="value">{{ summary.gapAnalysis.totalGaps }}</span>
          </div>
          <div class="summary-item">
            <span class="label">Critical:</span>
            <span class="value error">{{ summary.gapAnalysis.gapsBySeverity.critical || 0 }}</span>
          </div>
          <div class="summary-item">
            <span class="label">High:</span>
            <span class="value warning">{{ summary.gapAnalysis.gapsBySeverity.high || 0 }}</span>
          </div>
          <div class="summary-item">
            <span class="label">Medium:</span>
            <span class="value">{{ summary.gapAnalysis.gapsBySeverity.medium || 0 }}</span>
          </div>
          <div class="summary-item">
            <span class="label">Low:</span>
            <span class="value">{{ summary.gapAnalysis.gapsBySeverity.low || 0 }}</span>
          </div>
        </div>
        <div v-if="summary.gapAnalysis.topGaps.length > 0" class="top-gaps">
          <h4>Top Gaps</h4>
          <div class="gaps-list">
            <div
              v-for="gap in summary.gapAnalysis.topGaps"
              :key="gap.id"
              class="gap-item"
              :class="`severity-${gap.severity}`"
            >
              <div class="gap-header">
                <span class="severity-badge" :class="`badge-${gap.severity}`">
                  {{ gap.severity.toUpperCase() }}
                </span>
                <span class="priority">Priority: {{ gap.priority }}/10</span>
              </div>
              <div class="gap-title">{{ gap.title }}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  summary: {
    policyChanges: Array<{
      policyId: string;
      policyName: string;
      changeType: 'created' | 'modified' | 'deleted';
      changes: string[];
      affectedResources: string[];
      affectedApplications: string[];
      requiredActions: string[];
    }>;
    complianceStatus: {
      overallScore: number;
      policyScores: Array<{
        policyId: string;
        policyName: string;
        score: number;
        gaps: number;
      }>;
    };
    gapAnalysis: {
      totalGaps: number;
      gapsBySeverity: Record<string, number>;
      topGaps: Array<{
        id: string;
        title: string;
        severity: string;
        priority: number;
      }>;
    };
  };
}

const props = defineProps<Props>();

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'success';
  if (score >= 70) return 'warning';
  return 'error';
};
</script>

<style scoped>
.detailed-summary {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.section {
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.section h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.policy-changes-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.policy-change-card {
  padding: var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
  border-left: 4px solid var(--color-primary);
}

.change-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-sm);
}

.change-header h4 {
  margin: 0;
  font-size: var(--font-size-md);
  font-weight: var(--font-weight-semibold);
}

.change-type-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.change-type-badge.type-created {
  background: var(--color-success);
  color: white;
}

.change-type-badge.type-modified {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.change-type-badge.type-deleted {
  background: var(--color-error);
  color: white;
}

.change-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.changes-list ul,
.required-actions ul {
  margin: var(--spacing-xs) 0 0 var(--spacing-md);
  padding-left: var(--spacing-md);
}

.compliance-status {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.overall-score {
  text-align: center;
  padding: var(--spacing-lg);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-md);
}

.score-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.score-value {
  font-size: var(--font-size-4xl);
  font-weight: var(--font-weight-bold);
}

.score-value.success {
  color: var(--color-success);
}

.score-value.warning {
  color: var(--color-warning);
}

.score-value.error {
  color: var(--color-error);
}

.policy-scores h4 {
  margin: 0 0 var(--spacing-sm) 0;
  font-size: var(--font-size-md);
  font-weight: var(--font-weight-semibold);
}

.scores-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.score-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay-light);
  border-radius: var(--border-radius-sm);
}

.policy-name {
  flex: 1;
  font-weight: var(--font-weight-medium);
}

.score {
  font-weight: var(--font-weight-semibold);
  margin-right: var(--spacing-md);
}

.gaps-count {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.gap-summary {
  display: flex;
  gap: var(--spacing-lg);
  flex-wrap: wrap;
  margin-bottom: var(--spacing-lg);
}

.summary-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.summary-item .label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.summary-item .value {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-bold);
}

.summary-item .value.error {
  color: var(--color-error);
}

.summary-item .value.warning {
  color: var(--color-warning);
}

.top-gaps h4 {
  margin: var(--spacing-lg) 0 var(--spacing-md) 0;
  font-size: var(--font-size-md);
  font-weight: var(--font-weight-semibold);
}

.gaps-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
}

.gap-item {
  padding: var(--spacing-sm);
  border-radius: var(--border-radius-md);
  border-left: 4px solid;
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
}

.gap-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  margin-bottom: var(--spacing-xs);
}

.severity-badge {
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--border-radius-sm);
  font-size: var(--font-size-xs);
  font-weight: 600;
  text-transform: uppercase;
}

.severity-badge.badge-critical,
.severity-badge.badge-high {
  background: var(--color-error);
  color: white;
}

.severity-badge.badge-medium {
  background: var(--color-warning);
  color: var(--color-text-primary);
}

.severity-badge.badge-low {
  background: var(--color-text-secondary);
  color: white;
}

.priority {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.gap-title {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}
</style>
