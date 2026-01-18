<template>
  <div class="overall-score">
    <div class="score-label">Overall Compliance Score</div>
    <div class="score-value">{{ score.toFixed(1) }}%</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  score: number;
}>();
</script>

<style scoped>
.overall-score {
  background: var(--gradient-card-alt);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-2xl);
  text-align: center;
  margin-bottom: var(--spacing-xl);
  box-shadow: var(--shadow-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.score-value {
  font-size: var(--font-size-6xl);
  font-weight: var(--font-weight-bold);
  background: var(--gradient-primary);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: var(--spacing-lg) 0;
}

.score-label {
  color: var(--color-text-secondary);
  font-size: var(--font-size-lg);
  text-transform: uppercase;
  letter-spacing: var(--letter-spacing-widest);
  font-weight: var(--font-weight-medium);
}
</style>

