<template>
  <div class="executive-summary">
    <div class="summary-card">
      <h3>Security Posture</h3>
      <div class="posture-level" :class="postureClass">
        {{ securityPosture }}
      </div>
      <div class="posture-score">{{ overallScore }}%</div>
    </div>
    <div class="summary-card">
      <h3>Risk Level</h3>
      <div class="risk-level" :class="riskClass">
        {{ riskLevel }}
      </div>
      <div class="risk-score">{{ riskScore }}/100</div>
    </div>
    <div class="summary-card">
      <h3>Remediation Velocity</h3>
      <div class="velocity-value">
        {{ remediationVelocity }} issues/week
      </div>
      <div class="velocity-trend" :class="velocityTrendClass">
        <TrendingUp v-if="velocityTrend >= 0" class="trend-icon" />
        <TrendingDown v-else class="trend-icon" />
        {{ Math.abs(velocityTrend) }}% vs last period
      </div>
    </div>
    <div class="summary-card">
      <h3>ROI</h3>
      <div class="roi-value">
        ${{ roiSavings.toLocaleString() }} saved
      </div>
      <div class="roi-period">Last {{ timeRange }} days</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { TrendingUp, TrendingDown } from 'lucide-vue-next';

const props = defineProps<{
  overallScore: number;
  riskScore: number;
  remediationVelocity: number;
  velocityTrend: number;
  roiSavings: number;
  timeRange?: number;
}>();

const securityPosture = computed(() => {
  if (props.overallScore >= 90) return 'Excellent';
  if (props.overallScore >= 75) return 'Good';
  if (props.overallScore >= 60) return 'Fair';
  return 'Poor';
});

const postureClass = computed(() => {
  if (props.overallScore >= 90) return 'excellent';
  if (props.overallScore >= 75) return 'good';
  if (props.overallScore >= 60) return 'fair';
  return 'poor';
});

const riskLevel = computed(() => {
  if (props.riskScore >= 80) return 'Critical';
  if (props.riskScore >= 60) return 'High';
  if (props.riskScore >= 40) return 'Medium';
  return 'Low';
});

const riskClass = computed(() => {
  if (props.riskScore >= 80) return 'critical';
  if (props.riskScore >= 60) return 'high';
  if (props.riskScore >= 40) return 'medium';
  return 'low';
});

const velocityTrendClass = computed(() => {
  return props.velocityTrend >= 0 ? 'positive' : 'negative';
});
</script>

<style scoped>
.executive-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 20px;
  margin-bottom: 32px;
}

.summary-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
  text-align: center;
  transition: all 0.3s;
}

.summary-card:hover {
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
}

.summary-card h3 {
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
  margin: 0 0 12px 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.posture-level,
.risk-level {
  font-size: 1.5rem;
  font-weight: 700;
  margin-bottom: 8px;
}

.posture-level.excellent,
.risk-level.low {
  color: #22c55e;
}

.posture-level.good,
.risk-level.medium {
  color: #fbbf24;
}

.posture-level.fair,
.risk-level.high {
  color: #fc8181;
}

.posture-level.poor,
.risk-level.critical {
  color: #ef4444;
}

.posture-score,
.risk-score {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-top: 4px;
}

.velocity-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #4facfe;
  margin-bottom: 8px;
}

.velocity-trend {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 4px;
  font-size: 0.875rem;
  margin-top: 8px;
}

.velocity-trend.positive {
  color: #22c55e;
}

.velocity-trend.negative {
  color: #fc8181;
}

.trend-icon {
  width: 14px;
  height: 14px;
}

.roi-value {
  font-size: 1.75rem;
  font-weight: 700;
  color: #22c55e;
  margin-bottom: 8px;
}

.roi-period {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-top: 4px;
}
</style>

