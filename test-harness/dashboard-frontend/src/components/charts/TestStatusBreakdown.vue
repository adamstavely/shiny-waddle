<template>
  <div class="test-status-breakdown">
    <div v-if="!metrics" class="chart-empty">
      <p>No status data available</p>
    </div>
    <div v-else class="breakdown-container">
      <!-- Pie Chart (simplified as circles) -->
      <div class="pie-chart">
        <svg :width="size" :height="size" class="pie-svg">
          <circle
            :cx="center"
            :cy="center"
            :r="radius"
            fill="none"
            stroke="#2d3748"
            stroke-width="2"
          />
          <circle
            v-for="(segment, index) in segments"
            :key="index"
            :cx="center"
            :cy="center"
            :r="radius"
            :stroke="segment.color"
            :stroke-width="segmentWidth"
            :stroke-dasharray="`${segment.length} ${circumference}`"
            :stroke-dashoffset="segment.offset"
            fill="none"
            transform="rotate(-90)"
            :transform-origin="`${center} ${center}`"
            class="segment"
          />
        </svg>
      </div>

      <!-- Legend -->
      <div class="legend">
        <div
          v-for="(item, index) in statusItems"
          :key="index"
          class="legend-item"
        >
          <div class="legend-color" :style="{ backgroundColor: item.color }"></div>
          <div class="legend-label">{{ item.label }}</div>
          <div class="legend-value">{{ item.value }}</div>
          <div class="legend-percentage">({{ item.percentage }}%)</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Metrics {
  totalTests: number;
  passed: number;
  failed: number;
  partial: number;
  errors: number;
}

const props = defineProps<{
  metrics: Metrics;
}>();

const size = 200;
const center = size / 2;
const radius = 80;
const circumference = 2 * Math.PI * radius;
const segmentWidth = 20;

const statusItems = computed(() => {
  if (!props.metrics || props.metrics.totalTests === 0) return [];
  
  const total = props.metrics.totalTests;
  return [
    {
      label: 'Passed',
      value: props.metrics.passed,
      percentage: total > 0 ? ((props.metrics.passed / total) * 100).toFixed(1) : '0',
      color: '#48bb78',
    },
    {
      label: 'Failed',
      value: props.metrics.failed,
      percentage: total > 0 ? ((props.metrics.failed / total) * 100).toFixed(1) : '0',
      color: '#fc8181',
    },
    {
      label: 'Partial',
      value: props.metrics.partial,
      percentage: total > 0 ? ((props.metrics.partial / total) * 100).toFixed(1) : '0',
      color: '#ed8936',
    },
    {
      label: 'Errors',
      value: props.metrics.errors,
      percentage: total > 0 ? ((props.metrics.errors / total) * 100).toFixed(1) : '0',
      color: '#f56565',
    },
  ].filter(item => item.value > 0);
});

const segments = computed(() => {
  if (!props.metrics || props.metrics.totalTests === 0) return [];
  
  const total = props.metrics.totalTests;
  let offset = 0;
  
  return [
    {
      length: (props.metrics.passed / total) * circumference,
      offset: -offset,
      color: '#48bb78',
    },
    {
      length: (props.metrics.failed / total) * circumference,
      offset: -(offset += (props.metrics.passed / total) * circumference),
      color: '#fc8181',
    },
    {
      length: (props.metrics.partial / total) * circumference,
      offset: -(offset += (props.metrics.failed / total) * circumference),
      color: '#ed8936',
    },
    {
      length: (props.metrics.errors / total) * circumference,
      offset: -(offset += (props.metrics.partial / total) * circumference),
      color: '#f56565',
    },
  ].filter(seg => seg.length > 0);
});
</script>

<style scoped>
.test-status-breakdown {
  width: 100%;
}

.chart-empty {
  padding: 3rem;
  text-align: center;
  color: #718096;
}

.breakdown-container {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 3rem;
  flex-wrap: wrap;
}

.pie-chart {
  flex-shrink: 0;
}

.pie-svg {
  width: 200px;
  height: 200px;
}

.segment {
  transition: stroke-width 0.2s;
}

.segment:hover {
  stroke-width: 24;
  opacity: 0.9;
}

.legend {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.legend-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.legend-color {
  width: 16px;
  height: 16px;
  border-radius: 4px;
  flex-shrink: 0;
}

.legend-label {
  min-width: 80px;
  color: #e2e8f0;
  font-size: 0.875rem;
}

.legend-value {
  color: #ffffff;
  font-weight: 600;
  font-size: 0.875rem;
  min-width: 40px;
  text-align: right;
}

.legend-percentage {
  color: #718096;
  font-size: 0.75rem;
  min-width: 50px;
}
</style>

