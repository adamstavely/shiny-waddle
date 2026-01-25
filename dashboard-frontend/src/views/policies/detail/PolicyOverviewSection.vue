<template>
  <div class="policy-overview-section">
    <div class="overview-grid">
      <div class="info-card">
        <h3 class="card-title">
          <Info class="title-icon" />
          Policy Information
        </h3>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">Type</span>
            <span class="info-value">{{ policy.type.toUpperCase() }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Version</span>
            <span class="info-value">{{ policy.version }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Status</span>
            <StatusBadge :status="policy.status" />
          </div>
          <div class="info-item">
            <span class="info-label">Created</span>
            <span class="info-value">{{ formatDate(policy.createdAt) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Last Updated</span>
            <span class="info-value">{{ formatDate(policy.lastUpdated) }}</span>
          </div>
          <div v-if="policy.type === 'abac'" class="info-item">
            <span class="info-label">Effect</span>
            <span class="info-value">{{ policy.effect }}</span>
          </div>
          <div v-if="policy.type === 'abac'" class="info-item">
            <span class="info-label">Priority</span>
            <span class="info-value">{{ policy.priority }}</span>
          </div>
        </div>
      </div>

      <div class="stats-card">
        <h3 class="card-title">
          <BarChart3 class="title-icon" />
          Statistics
        </h3>
        <div class="stats-list">
          <div class="stat-item">
            <span class="stat-label">Total Rules/Conditions</span>
            <span class="stat-value">{{ policy.ruleCount }}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Test Coverage</span>
            <span class="stat-value">{{ policy.testCoverage || 'N/A' }}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Violations Detected</span>
            <span class="stat-value">{{ policy.violationsDetected || 0 }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Info, BarChart3 } from 'lucide-vue-next';
import StatusBadge from '../../../components/StatusBadge.vue';

import type { Policy } from '../../../types/test';

interface Props {
  policy: Policy;
}

defineProps<Props>();

const formatDate = (date: Date | string | null | undefined): string => {
  if (!date) return 'N/A';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};
</script>

<style scoped>
.policy-overview-section {
  margin-bottom: var(--spacing-xl);
}

.overview-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: var(--spacing-lg);
}

.info-card,
.stats-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.card-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-md) 0;
}

.title-icon {
  width: 20px;
  height: 20px;
  color: var(--color-primary);
}

.info-list,
.stats-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
}

.info-item,
.stat-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-bottom: var(--spacing-sm);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
}

.info-item:last-child,
.stat-item:last-child {
  border-bottom: none;
}

.info-label,
.stat-label {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.info-value,
.stat-value {
  font-size: var(--font-size-base);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}
</style>
