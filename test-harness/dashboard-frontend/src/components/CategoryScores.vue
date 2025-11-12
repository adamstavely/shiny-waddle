<template>
  <div class="card">
    <h2>
      <BarChart3 class="title-icon" />
      By Category
    </h2>
    <div v-if="Object.keys(categories).length === 0" class="empty">
      No category data available
    </div>
    <div v-else>
      <div
        v-for="(score, category) in categories"
        :key="category"
        class="metric"
      >
        <div class="metric-content">
          <span class="metric-label">{{ formatCategory(category) }}</span>
          <div class="progress-bar">
            <div
              class="progress-fill"
              :style="{ width: `${score}%` }"
            ></div>
          </div>
        </div>
        <span class="metric-value">{{ score.toFixed(1) }}%</span>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { BarChart3 } from 'lucide-vue-next';

defineProps<{
  categories: Record<string, number>;
}>();

const formatCategory = (category: string): string => {
  return category
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (str) => str.toUpperCase())
    .trim();
};
</script>

<style scoped>
.card {
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.card h2 {
  color: #ffffff;
  margin-bottom: 20px;
  font-size: 1.5em;
  border-bottom: 2px solid #4facfe;
  padding-bottom: 10px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 12px;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.metric:last-child {
  border-bottom: none;
}

.metric-content {
  flex: 1;
  margin-right: 20px;
}

.metric-label {
  color: #a0aec0;
  font-size: 1em;
  display: block;
  margin-bottom: 10px;
}

.progress-bar {
  width: 100%;
  height: 8px;
  background: rgba(79, 172, 254, 0.1);
  border-radius: 4px;
  overflow: hidden;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #4facfe 0%, #00f2fe 100%);
  transition: width 0.3s ease;
  box-shadow: 0 0 10px rgba(79, 172, 254, 0.5);
}

.metric-value {
  font-size: 1.5em;
  font-weight: bold;
  color: #4facfe;
}

.empty {
  text-align: center;
  color: #718096;
  padding: 20px;
}
</style>

