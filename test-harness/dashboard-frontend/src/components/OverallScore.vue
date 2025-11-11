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
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 40px;
  text-align: center;
  margin-bottom: 30px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.score-value {
  font-size: 5em;
  font-weight: bold;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 20px 0;
}

.score-label {
  color: #a0aec0;
  font-size: 1.2em;
  text-transform: uppercase;
  letter-spacing: 2px;
  font-weight: 500;
}
</style>

