<template>
  <div class="executive-summary">
    <div class="summary-text">
      <p>{{ summary.summary }}</p>
    </div>

    <div class="key-metrics">
      <h3>Key Metrics</h3>
      <div class="metrics-grid">
        <div class="metric-card">
          <div class="metric-label">Policies Created</div>
          <div class="metric-value">{{ summary.keyMetrics.policiesCreated }}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Policies Modified</div>
          <div class="metric-value">{{ summary.keyMetrics.policiesModified }}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Compliance Score</div>
          <div class="metric-value" :class="getScoreClass(summary.keyMetrics.complianceScore)">
            {{ summary.keyMetrics.complianceScore }}%
          </div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Total Gaps</div>
          <div class="metric-value">{{ summary.keyMetrics.totalGaps }}</div>
        </div>
        <div class="metric-card">
          <div class="metric-label">Critical Gaps</div>
          <div class="metric-value error">{{ summary.keyMetrics.criticalGaps }}</div>
        </div>
      </div>
    </div>

    <div class="key-changes">
      <h3>Key Changes</h3>
      <ul>
        <li v-for="(change, index) in summary.keyChanges" :key="index">
          {{ change }}
        </li>
      </ul>
    </div>

    <div class="impact">
      <h3>Impact</h3>
      <div class="impact-details">
        <div class="impact-item">
          <span class="impact-label">Resources Affected:</span>
          <span class="impact-value">{{ summary.impact.resourcesAffected }}</span>
        </div>
        <div class="impact-item">
          <span class="impact-label">Applications Affected:</span>
          <span class="impact-value">{{ summary.impact.applicationsAffected }}</span>
        </div>
        <div class="impact-item">
          <span class="impact-label">Estimated Effort:</span>
          <span class="impact-value">{{ summary.impact.estimatedEffort }}</span>
        </div>
      </div>
    </div>

    <div class="recommendations">
      <h3>Recommendations</h3>
      <ul>
        <li v-for="(rec, index) in summary.recommendations" :key="index">
          {{ rec }}
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup lang="ts">
interface Props {
  summary: {
    summary: string;
    keyMetrics: {
      policiesCreated: number;
      policiesModified: number;
      policiesDeleted: number;
      complianceScore: number;
      totalGaps: number;
      criticalGaps: number;
    };
    keyChanges: string[];
    impact: {
      resourcesAffected: number;
      applicationsAffected: number;
      estimatedEffort: string;
    };
    recommendations: string[];
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
.executive-summary {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
}

.summary-text {
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
  border-left: 4px solid var(--color-primary);
}

.summary-text p {
  margin: 0;
  line-height: 1.8;
  color: var(--color-text-primary);
  white-space: pre-line;
}

.key-metrics h3,
.key-changes h3,
.impact h3,
.recommendations h3 {
  margin: 0 0 var(--spacing-md) 0;
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--spacing-md);
}

.metric-card {
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
}

.metric-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin-bottom: var(--spacing-xs);
}

.metric-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-text-primary);
}

.metric-value.success {
  color: var(--color-success);
}

.metric-value.warning {
  color: var(--color-warning);
}

.metric-value.error {
  color: var(--color-error);
}

.key-changes ul,
.recommendations ul {
  margin: 0;
  padding-left: var(--spacing-lg);
}

.key-changes li,
.recommendations li {
  margin-bottom: var(--spacing-sm);
  line-height: 1.6;
  color: var(--color-text-primary);
}

.impact-details {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-sm);
  padding: var(--spacing-md);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-md);
}

.impact-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.impact-label {
  font-weight: var(--font-weight-medium);
  color: var(--color-text-secondary);
}

.impact-value {
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
}
</style>
