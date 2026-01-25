<template>
  <div class="compliance-score-card">
    <div class="score-header">
      <h2>Compliance Score</h2>
      <div class="trend-indicator" :class="`trend-${trend}`">
        <TrendingUp v-if="trend === 'up'" class="trend-icon" />
        <TrendingDown v-else-if="trend === 'down'" class="trend-icon" />
        <Minus v-else class="trend-icon" />
        <span class="trend-text">{{ trendText }}</span>
      </div>
    </div>
    <div class="score-display">
      <div class="current-score" :class="getScoreClass(currentScore)">
        {{ currentScore }}
      </div>
      <div class="score-label">out of 100</div>
    </div>
    <div class="score-change" :class="`change-${trend}`">
      <span v-if="scoreChange !== 0">
        {{ scoreChange > 0 ? '+' : '' }}{{ scoreChange }} points
      </span>
      <span v-else>No change</span>
      <span class="change-label">from previous</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { TrendingUp, TrendingDown, Minus } from 'lucide-vue-next';

const props = defineProps<{
  currentScore: number;
  previousScore: number;
  trend: 'up' | 'down' | 'stable';
  scoreChange: number;
}>();

const trendText = computed(() => {
  if (props.trend === 'up') return 'Improving';
  if (props.trend === 'down') return 'Declining';
  return 'Stable';
});

const getScoreClass = (score: number): string => {
  if (score >= 90) return 'score-excellent';
  if (score >= 75) return 'score-good';
  if (score >= 60) return 'score-fair';
  return 'score-poor';
};
</script>

<style scoped>
.compliance-score-card {
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
}

.score-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-lg);
}

.score-header h2 {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.trend-indicator {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  padding: var(--spacing-sm) var(--spacing-md);
  border-radius: var(--border-radius-md);
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
}

.trend-indicator.trend-up {
  background: var(--color-success-bg);
  color: var(--color-success);
  border: var(--border-width-thin) solid var(--color-success);
  opacity: 0.3;
}

.trend-indicator.trend-down {
  background: var(--color-error-bg);
  color: var(--color-error);
  border: var(--border-width-thin) solid var(--color-error);
  opacity: 0.3;
}

.trend-indicator.trend-stable {
  background: var(--color-bg-tertiary);
  opacity: 0.6;
  color: var(--color-text-secondary);
  border: var(--border-width-thin) solid var(--color-text-muted);
  opacity: 0.3;
}

.trend-icon {
  width: 16px;
  height: 16px;
}

.score-display {
  text-align: center;
  margin-bottom: 16px;
}

.current-score {
  font-size: var(--font-size-5xl);
  font-weight: var(--font-weight-bold);
  line-height: 1;
  margin-bottom: var(--spacing-sm);
}

.current-score.score-excellent {
  color: var(--color-success);
}

.current-score.score-good {
  color: var(--color-primary);
}

.current-score.score-fair {
  color: var(--color-warning);
}

.current-score.score-poor {
  color: var(--color-error);
}

.score-label {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
}

.score-change {
  text-align: center;
  font-size: var(--font-size-sm);
}

.score-change.change-up {
  color: var(--color-success);
}

.score-change.change-down {
  color: var(--color-error);
}

.score-change.change-stable {
  color: var(--color-text-secondary);
}

.change-label {
  display: block;
  margin-top: var(--spacing-xs);
  color: var(--color-text-muted);
  font-size: var(--font-size-xs);
}
</style>

