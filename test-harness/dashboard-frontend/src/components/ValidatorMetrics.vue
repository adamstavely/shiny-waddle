<template>
  <div class="validator-metrics">
    <h3 class="metrics-title">Validator Metrics</h3>
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-header">
          <Shield class="metric-icon" />
          <span class="metric-label">Active Validators</span>
        </div>
        <div class="metric-value">{{ activeValidators }}</div>
        <div class="metric-detail">of {{ totalValidators }} total</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <TestTube class="metric-icon" />
          <span class="metric-label">Tests Executed</span>
        </div>
        <div class="metric-value">{{ totalTests }}</div>
        <div class="metric-detail">across all validators</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <CheckCircle2 class="metric-icon" />
          <span class="metric-label">Success Rate</span>
        </div>
        <div class="metric-value" :class="getSuccessRateClass()">{{ overallSuccessRate }}%</div>
        <div class="metric-detail">average across validators</div>
      </div>
    </div>

    <!-- Validator Breakdown Charts -->
    <div class="validator-charts" v-if="validators.length > 0">
      <div class="charts-grid">
        <!-- Pie Chart: Distribution of Tests by Validator -->
        <div class="chart-card">
          <h4 class="chart-title">Tests by Validator</h4>
          <div class="chart-container">
            <svg class="pie-chart" viewBox="0 0 200 200">
              <g v-for="(segment, index) in pieChartData" :key="index">
                <path
                  :d="segment.path"
                  :fill="segment.color"
                  stroke="#1a1f2e"
                  stroke-width="2"
                  class="pie-segment"
                />
                <text
                  v-if="segment.percentage > 5"
                  :x="segment.labelX"
                  :y="segment.labelY"
                  text-anchor="middle"
                  fill="#ffffff"
                  font-size="10"
                  font-weight="600"
                >
                  {{ segment.percentage }}%
                </text>
              </g>
            </svg>
            <div class="chart-legend">
              <div
                v-for="(item, index) in pieChartData"
                :key="index"
                class="legend-item"
              >
                <span class="legend-color" :style="{ backgroundColor: item.color }"></span>
                <span class="legend-label">{{ item.name }}</span>
                <span class="legend-value">{{ item.value }} tests</span>
              </div>
            </div>
          </div>
        </div>

        <!-- Bar Chart: Success Rate by Validator -->
        <div class="chart-card">
          <h4 class="chart-title">Success Rate by Validator</h4>
          <div class="chart-container">
            <div class="bar-chart">
              <div
                v-for="validator in validatorsWithTests"
                :key="validator.id"
                class="bar-item"
              >
                <div class="bar-label">{{ validator.name }}</div>
                <div class="bar-wrapper">
                  <div
                    class="bar-fill"
                    :style="{
                      width: `${getValidatorSuccessRate(validator)}%`,
                      backgroundColor: getValidatorColor(validator)
                    }"
                  ></div>
                  <span class="bar-value">{{ getValidatorSuccessRate(validator) }}%</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <div class="validators-breakdown" v-if="validators.length > 0">
      <h4 class="breakdown-title">By Validator</h4>
      <div class="breakdown-list">
        <div
          v-for="validator in validators"
          :key="validator.id"
          class="breakdown-item"
        >
          <div class="breakdown-header">
            <span class="breakdown-name">{{ validator.name }}</span>
            <span class="breakdown-status" :class="validator.enabled ? 'status-enabled' : 'status-disabled'">
              {{ validator.enabled ? 'Enabled' : 'Disabled' }}
            </span>
          </div>
          <div class="breakdown-stats">
            <span class="stat">{{ validator.testCount || 0 }} tests</span>
            <span class="stat" :class="getValidatorSuccessRateClass(validator)">
              {{ getValidatorSuccessRate(validator) }}% success
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { Shield, TestTube, CheckCircle2 } from 'lucide-vue-next';

interface Validator {
  id: string;
  name: string;
  enabled: boolean;
  testCount?: number;
  successCount?: number;
  failureCount?: number;
}

const props = defineProps<{
  validators: Validator[];
}>();

const totalValidators = computed(() => props.validators.length);
const activeValidators = computed(() => props.validators.filter(v => v.enabled).length);
const totalTests = computed(() => {
  return props.validators.reduce((sum, v) => sum + (v.testCount || 0), 0);
});

const overallSuccessRate = computed(() => {
  const total = totalTests.value;
  if (total === 0) return 0;
  const success = props.validators.reduce((sum, v) => sum + (v.successCount || 0), 0);
  return Math.round((success / total) * 100);
});

const getSuccessRateClass = (): string => {
  const rate = overallSuccessRate.value;
  if (rate >= 90) return 'rate-high';
  if (rate >= 70) return 'rate-medium';
  return 'rate-low';
};

const getValidatorSuccessRate = (validator: Validator): number => {
  if (!validator.testCount || validator.testCount === 0) return 0;
  const success = validator.successCount || 0;
  return Math.round((success / validator.testCount) * 100);
};

const getValidatorSuccessRateClass = (validator: Validator): string => {
  const rate = getValidatorSuccessRate(validator);
  if (rate >= 90) return 'rate-high';
  if (rate >= 70) return 'rate-medium';
  return 'rate-low';
};

const getValidatorColor = (validator: Validator): string => {
  const rate = getValidatorSuccessRate(validator);
  if (rate >= 90) return '#22c55e';
  if (rate >= 70) return '#fbbf24';
  return '#fc8181';
};

const validatorsWithTests = computed(() => {
  return props.validators.filter(v => (v.testCount || 0) > 0);
});

const pieChartData = computed(() => {
  const colors = ['#4facfe', '#00f2fe', '#22c55e', '#fbbf24', '#fc8181', '#a855f7', '#ec4899'];
  const validatorsWithData = props.validators.filter(v => (v.testCount || 0) > 0);
  const total = totalTests.value;
  
  if (total === 0) return [];

  let currentAngle = -90; // Start at top
  const radius = 80;
  const centerX = 100;
  const centerY = 100;

  return validatorsWithData.map((validator, index) => {
    const value = validator.testCount || 0;
    const percentage = Math.round((value / total) * 100);
    const angle = (value / total) * 360;
    
    const startAngle = currentAngle;
    const endAngle = currentAngle + angle;
    
    const startAngleRad = (startAngle * Math.PI) / 180;
    const endAngleRad = (endAngle * Math.PI) / 180;
    
    const x1 = centerX + radius * Math.cos(startAngleRad);
    const y1 = centerY + radius * Math.sin(startAngleRad);
    const x2 = centerX + radius * Math.cos(endAngleRad);
    const y2 = centerY + radius * Math.sin(endAngleRad);
    
    const largeArcFlag = angle > 180 ? 1 : 0;
    
    const path = `M ${centerX} ${centerY} L ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2} Z`;
    
    // Label position (middle of arc)
    const labelAngle = (startAngle + angle / 2) * Math.PI / 180;
    const labelRadius = radius * 0.7;
    const labelX = centerX + labelRadius * Math.cos(labelAngle);
    const labelY = centerY + labelRadius * Math.sin(labelAngle);
    
    currentAngle += angle;
    
    return {
      name: validator.name,
      value,
      percentage,
      color: colors[index % colors.length],
      path,
      labelX,
      labelY,
    };
  });
});
</script>

<style scoped>
.validator-metrics {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 24px;
}

.metrics-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 20px;
}

.metrics-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}

.metric-card {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.metric-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}

.metric-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
}

.metric-label {
  font-size: 0.875rem;
  color: #718096;
  font-weight: 500;
}

.metric-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 4px;
}

.metric-value.rate-high {
  color: #22c55e;
}

.metric-value.rate-medium {
  color: #fbbf24;
}

.metric-value.rate-low {
  color: #fc8181;
}

.metric-detail {
  font-size: 0.75rem;
  color: #a0aec0;
}

.validators-breakdown {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.breakdown-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.breakdown-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.breakdown-item {
  padding: 12px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.breakdown-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

.breakdown-name {
  font-size: 0.9rem;
  font-weight: 500;
  color: #ffffff;
}

.breakdown-status {
  padding: 2px 8px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status-enabled {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-disabled {
  background: rgba(156, 163, 175, 0.2);
  color: #9ca3af;
}

.breakdown-stats {
  display: flex;
  gap: 16px;
  font-size: 0.875rem;
  color: #a0aec0;
}

.breakdown-stats .stat {
  color: #a0aec0;
}

.breakdown-stats .stat.rate-high {
  color: #22c55e;
}

.breakdown-stats .stat.rate-medium {
  color: #fbbf24;
}

.breakdown-stats .stat.rate-low {
  color: #fc8181;
}

/* Charts Styles */
.validator-charts {
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.charts-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
  gap: 24px;
}

.chart-card {
  padding: 20px;
  background: rgba(15, 20, 25, 0.4);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.chart-title {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.chart-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.pie-chart {
  width: 100%;
  height: 200px;
  max-width: 200px;
  margin: 0 auto;
}

.pie-segment {
  transition: opacity 0.2s;
  cursor: pointer;
}

.pie-segment:hover {
  opacity: 0.8;
}

.chart-legend {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.875rem;
}

.legend-color {
  width: 12px;
  height: 12px;
  border-radius: 3px;
  flex-shrink: 0;
}

.legend-label {
  flex: 1;
  color: #a0aec0;
}

.legend-value {
  color: #ffffff;
  font-weight: 500;
}

.bar-chart {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.bar-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.bar-label {
  font-size: 0.875rem;
  color: #a0aec0;
  font-weight: 500;
}

.bar-wrapper {
  position: relative;
  width: 100%;
  height: 24px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 6px;
  overflow: hidden;
}

.bar-fill {
  height: 100%;
  transition: width 0.3s ease;
  border-radius: 6px;
}

.bar-value {
  position: absolute;
  right: 8px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 0.75rem;
  font-weight: 600;
  color: #ffffff;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
}
</style>

