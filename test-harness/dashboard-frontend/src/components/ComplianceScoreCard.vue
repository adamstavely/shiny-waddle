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
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 32px;
}

.score-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.score-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.trend-indicator {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
}

.trend-indicator.trend-up {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.trend-indicator.trend-down {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.trend-indicator.trend-stable {
  background: rgba(160, 174, 192, 0.1);
  color: #a0aec0;
  border: 1px solid rgba(160, 174, 192, 0.3);
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
  font-size: 4rem;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 8px;
}

.current-score.score-excellent {
  color: #22c55e;
}

.current-score.score-good {
  color: #4facfe;
}

.current-score.score-fair {
  color: #fbbf24;
}

.current-score.score-poor {
  color: #fc8181;
}

.score-label {
  font-size: 1rem;
  color: #a0aec0;
}

.score-change {
  text-align: center;
  font-size: 0.875rem;
}

.score-change.change-up {
  color: #22c55e;
}

.score-change.change-down {
  color: #fc8181;
}

.score-change.change-stable {
  color: #a0aec0;
}

.change-label {
  display: block;
  margin-top: 4px;
  color: #718096;
  font-size: 0.75rem;
}
</style>

