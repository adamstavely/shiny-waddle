<template>
  <div class="risk-trends">
    <h3 class="section-title">Risk Trends</h3>
    <div class="risk-overview">
      <div class="risk-summary">
        <div class="risk-item">
          <div class="risk-label">Current Risk Score</div>
          <div class="risk-value" :class="riskClass">{{ currentRisk }}/100</div>
        </div>
        <div class="risk-item">
          <div class="risk-label">Trend</div>
          <div class="risk-trend-value" :class="trendClass">
            <TrendingUp v-if="riskTrend >= 0" class="trend-icon" />
            <TrendingDown v-else class="trend-icon" />
            {{ Math.abs(riskTrend) }}% vs last period
          </div>
        </div>
      </div>
    </div>
    <div class="risk-charts">
      <div class="chart-card">
        <h4>Risk Score Over Time</h4>
        <LineChart
          v-if="riskData.length > 0"
          :data="{ data: riskData }"
          :height="200"
          color="#fc8181"
        />
        <div v-else class="no-data">No risk data available</div>
      </div>
      <div class="chart-card">
        <h4>Risk Distribution</h4>
        <BarChart
          v-if="riskDistribution.length > 0"
          :data="riskDistribution"
          :height="200"
          color="#fbbf24"
        />
        <div v-else class="no-data">No distribution data available</div>
      </div>
    </div>
    <div class="top-risks">
      <h4>Top Risks</h4>
      <div class="risks-list">
        <div
          v-for="(risk, index) in topRisks"
          :key="index"
          class="risk-entry"
        >
          <div class="risk-rank">{{ index + 1 }}</div>
          <div class="risk-info">
            <div class="risk-name">{{ risk.name }}</div>
            <div class="risk-severity" :class="`severity-${risk.severity}`">
              {{ risk.severity }}
            </div>
          </div>
          <div class="risk-score">{{ risk.score }}/100</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { TrendingUp, TrendingDown } from 'lucide-vue-next';
import LineChart from '../charts/LineChart.vue';
import BarChart from '../charts/BarChart.vue';

const props = defineProps<{
  currentRisk: number;
  riskTrend: number;
  riskData: Array<{ date: string; value: number }>;
  riskDistribution: Array<{ name: string; value: number }>;
  topRisks: Array<{ name: string; severity: string; score: number }>;
}>();

const riskClass = computed(() => {
  if (props.currentRisk >= 80) return 'critical';
  if (props.currentRisk >= 60) return 'high';
  if (props.currentRisk >= 40) return 'medium';
  return 'low';
});

const trendClass = computed(() => {
  return props.riskTrend >= 0 ? 'negative' : 'positive';
});
</script>

<style scoped>
.risk-trends {
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

.risk-overview {
  margin-bottom: 24px;
}

.risk-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
}

.risk-item {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 12px;
  padding: 16px;
}

.risk-label {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-bottom: 8px;
}

.risk-value {
  font-size: 1.5rem;
  font-weight: 700;
}

.risk-value.critical {
  color: #ef4444;
}

.risk-value.high {
  color: #fc8181;
}

.risk-value.medium {
  color: #fbbf24;
}

.risk-value.low {
  color: #22c55e;
}

.risk-trend-value {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 1rem;
  font-weight: 600;
}

.risk-trend-value.positive {
  color: #22c55e;
}

.risk-trend-value.negative {
  color: #fc8181;
}

.trend-icon {
  width: 16px;
  height: 16px;
}

.risk-charts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 20px;
  margin-bottom: 24px;
}

.chart-card {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 12px;
  padding: 20px;
}

.chart-card h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.no-data {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 200px;
  color: #a0aec0;
}

.top-risks {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.1);
  border-radius: 12px;
  padding: 20px;
}

.top-risks h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.risks-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.risk-entry {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
}

.risk-rank {
  width: 32px;
  height: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  font-weight: 600;
  color: #4facfe;
  flex-shrink: 0;
}

.risk-info {
  flex: 1;
}

.risk-name {
  font-size: 0.95rem;
  font-weight: 500;
  color: #ffffff;
  margin-bottom: 4px;
}

.risk-severity {
  font-size: 0.75rem;
  padding: 2px 8px;
  border-radius: 4px;
  display: inline-block;
}

.severity-critical {
  background: rgba(239, 68, 68, 0.2);
  color: #ef4444;
}

.severity-high {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.severity-medium {
  background: rgba(251, 191, 36, 0.2);
  color: #fbbf24;
}

.severity-low {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.risk-score {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
}
</style>

