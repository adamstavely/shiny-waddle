<template>
  <div class="remediation-velocity">
    <h3 class="section-title">Remediation Velocity</h3>
    <div class="velocity-metrics">
      <div class="metric-card">
        <div class="metric-label">Issues Fixed This Week</div>
        <div class="metric-value">{{ currentWeek }}</div>
        <div class="metric-change" :class="weekChangeClass">
          <TrendingUp v-if="weekChange >= 0" class="change-icon" />
          <TrendingDown v-else class="change-icon" />
          {{ Math.abs(weekChange) }} vs last week
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Average MTTR</div>
        <div class="metric-value">{{ mttr }} days</div>
        <div class="metric-change" :class="mttrChangeClass">
          <TrendingUp v-if="mttrChange <= 0" class="change-icon" />
          <TrendingDown v-else class="change-icon" />
          {{ Math.abs(mttrChange) }} days vs last period
        </div>
      </div>
      <div class="metric-card">
        <div class="metric-label">Open Issues</div>
        <div class="metric-value">{{ openIssues }}</div>
        <div class="metric-change" :class="openIssuesChangeClass">
          <TrendingUp v-if="openIssuesChange <= 0" class="change-icon" />
          <TrendingDown v-else class="change-icon" />
          {{ Math.abs(openIssuesChange) }} vs last week
        </div>
      </div>
    </div>
    <div class="velocity-chart">
      <LineChart
        v-if="velocityData.length > 0"
        :data="{ data: velocityData }"
        :height="200"
        color="#4facfe"
      />
      <div v-else class="no-data">No velocity data available</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { TrendingUp, TrendingDown } from 'lucide-vue-next';
import LineChart from '../charts/LineChart.vue';

const props = defineProps<{
  currentWeek: number;
  weekChange: number;
  mttr: number;
  mttrChange: number;
  openIssues: number;
  openIssuesChange: number;
  velocityData: Array<{ date: string; value: number }>;
}>();

const weekChangeClass = computed(() => {
  return props.weekChange >= 0 ? 'positive' : 'negative';
});

const mttrChangeClass = computed(() => {
  return props.mttrChange <= 0 ? 'positive' : 'negative';
});

const openIssuesChangeClass = computed(() => {
  return props.openIssuesChange <= 0 ? 'positive' : 'negative';
});
</script>

<style scoped>
.remediation-velocity {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  margin-bottom: 24px;
}

.section-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
}

.velocity-metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.metric-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 12px;
  padding: 16px;
}

.metric-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.metric-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.metric-change {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 0.875rem;
}

.metric-change.positive {
  color: #22c55e;
}

.metric-change.negative {
  color: #fc8181;
}

.change-icon {
  width: 14px;
  height: 14px;
}

.velocity-chart {
  width: 100%;
  height: 200px;
}

.no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #a0aec0;
}
</style>

