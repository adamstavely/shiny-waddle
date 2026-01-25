<template>
  <div class="test-suite-overview-tab">
    <div class="overview-grid">
      <div class="info-card">
        <h3 class="card-title">
          <Info class="title-icon" />
          Suite Information
        </h3>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">Name</span>
            <span class="info-value">{{ suite.name }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Application</span>
            <span class="info-value">{{ suite.application || suite.applicationId }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Team</span>
            <span class="info-value">{{ suite.team }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Status</span>
            <StatusBadge :status="suite.status" />
          </div>
          <div class="info-item">
            <span class="info-label">Source Type</span>
            <span class="info-value">{{ suite.sourceType || 'json' }}</span>
          </div>
          <div v-if="suite.sourcePath" class="info-item">
            <span class="info-label">Source Path</span>
            <span class="info-value source-path-value">{{ suite.sourcePath }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Created</span>
            <span class="info-value">{{ formatDate(suite.createdAt) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Last Updated</span>
            <span class="info-value">{{ formatDate(suite.updatedAt) }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Last Run</span>
            <span class="info-value">{{ formatDate(suite.lastRun) }}</span>
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
            <span class="stat-label">Test Count</span>
            <span class="stat-value">{{ suite.testCount || 0 }}</span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Score</span>
            <span class="stat-value score" :class="getScoreClass(suite.score)">
              {{ suite.score || 0 }}%
            </span>
          </div>
          <div class="stat-item">
            <span class="stat-label">Test Types</span>
            <span class="stat-value">{{ suite.testTypes?.length || 0 }}</span>
          </div>
        </div>
        <div v-if="suite.testTypes && suite.testTypes.length > 0" class="test-types-list">
          <StatusBadge
            v-for="type in suite.testTypes"
            :key="type"
            :status="type"
            size="sm"
          />
        </div>
      </div>

      <!-- Baseline Config Card (for platform config test suites) -->
      <div v-if="suite.baselineConfig" class="baseline-card">
        <h3 class="card-title">
          <Settings class="title-icon" />
          Baseline Configuration
        </h3>
        <div class="info-list">
          <div class="info-item">
            <span class="info-label">Platform</span>
            <span class="info-value">{{ suite.baselineConfig.platform }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Environment</span>
            <span class="info-value">{{ suite.baselineConfig.environment }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Version</span>
            <span class="info-value">{{ suite.baselineConfig.version }}</span>
          </div>
          <div class="info-item">
            <span class="info-label">Config Keys</span>
            <span class="info-value">{{ Object.keys(suite.baselineConfig.config || {}).length }} configured</span>
          </div>
        </div>
        <div v-if="suite.baselineConfig.config" class="config-preview">
          <details>
            <summary class="config-summary">View Configuration</summary>
            <pre class="config-json">{{ JSON.stringify(suite.baselineConfig.config, null, 2) }}</pre>
          </details>
        </div>
      </div>
    </div>
    
    <!-- Cross Links -->
    <CrossLinkPanel
      v-if="suite"
      entity-type="test-suite"
      :entity-id="suite.id"
    />
  </div>
</template>

<script setup lang="ts">
import { Info, BarChart3, Settings } from 'lucide-vue-next';
import StatusBadge from '../../components/StatusBadge.vue';
import CrossLinkPanel from '../../components/CrossLinkPanel.vue';

import type { TestSuite } from '../../../types/test';

interface Props {
  suite: TestSuite;
}

defineProps<Props>();

const formatDate = (date: Date | string | null | undefined): string => {
  if (!date) return 'Never';
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

const getScoreClass = (score: number | null | undefined): string => {
  if (!score) return '';
  if (score >= 90) return 'score-excellent';
  if (score >= 70) return 'score-good';
  if (score >= 50) return 'score-fair';
  return 'score-poor';
};
</script>

<style scoped>
.test-suite-overview-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xl);
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

.source-path-value {
  font-family: monospace;
  font-size: var(--font-size-sm);
}

.score {
  font-weight: var(--font-weight-bold);
}

.score-excellent {
  color: var(--color-success);
}

.score-good {
  color: var(--color-primary);
}

.score-fair {
  color: var(--color-warning);
}

.score-poor {
  color: var(--color-error);
}

.test-types-list {
  display: flex;
  flex-wrap: wrap;
  gap: var(--spacing-xs);
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.baseline-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.config-preview {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-muted);
}

.config-summary {
  cursor: pointer;
  color: var(--color-primary);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  margin-bottom: var(--spacing-sm);
}

.config-summary:hover {
  color: var(--color-primary-hover);
}

.config-json {
  background: rgba(0, 0, 0, 0.3);
  border: var(--border-width-thin) solid var(--border-color-muted);
  border-radius: var(--border-radius-md);
  padding: var(--spacing-md);
  font-family: monospace;
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
  overflow-x: auto;
  max-height: 400px;
  overflow-y: auto;
}
</style>
