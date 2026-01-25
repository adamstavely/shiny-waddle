<template>
  <div class="distribution-chart">
    <svg :viewBox="`0 0 ${width} ${height}`" class="chart-svg" preserveAspectRatio="none">
      <!-- Grid lines -->
      <g v-for="i in 5" :key="`grid-${i}`" class="grid-line">
        <line
          :x1="padding"
          :y1="padding + (i - 1) * (chartHeight / 4)"
          :x2="width - padding"
          :y2="padding + (i - 1) * (chartHeight / 4)"
          stroke="rgba(79, 172, 254, 0.1)"
          stroke-width="1"
        />
      </g>
      
      <!-- Bars -->
      <g v-for="(bar, index) in bars" :key="`bar-${index}`">
        <rect
          :x="bar.x"
          :y="bar.y"
          :width="bar.width"
          :height="bar.height"
          :fill="getBarColor(bar.value)"
          rx="4"
          class="bar"
        />
        <text
          :x="bar.x + bar.width / 2"
          :y="bar.y - 5"
          text-anchor="middle"
          fill="#ffffff"
          font-size="11"
          font-weight="600"
        >
          {{ bar.value }}
        </text>
        <text
          :x="bar.x + bar.width / 2"
          :y="height - padding + 20"
          text-anchor="middle"
          fill="#a0aec0"
          font-size="10"
        >
          {{ bar.label }}
        </text>
      </g>
      
      <!-- Y-axis labels -->
      <text
        v-for="(label, index) in yAxisLabels"
        :key="`ylabel-${index}`"
        :x="padding - 10"
        :y="padding + index * (chartHeight / 4) + 4"
        text-anchor="end"
        fill="#a0aec0"
        font-size="10"
      >
        {{ label }}
      </text>
    </svg>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Props {
  data: Array<{ range: string; count: number }>;
  height?: number;
}

const props = withDefaults(defineProps<Props>(), {
  height: 250
});

const width = 600;
const padding = 40;
const chartHeight = computed(() => props.height - padding * 2);

const maxValue = computed(() => {
  if (props.data.length === 0) return 1;
  return Math.max(...props.data.map(d => d.count), 1);
});

const bars = computed(() => {
  if (props.data.length === 0) return [];
  
  const barWidth = (width - padding * 2) / props.data.length - 10;
  const maxBarHeight = chartHeight.value;
  
  return props.data.map((item, index) => {
    const x = padding + index * ((width - padding * 2) / props.data.length);
    const height = (item.count / maxValue.value) * maxBarHeight;
    const y = padding + maxBarHeight - height;
    
    return {
      x,
      y,
      width: barWidth,
      height,
      value: item.count,
      label: item.range
    };
  });
});

const yAxisLabels = computed(() => {
  const labels: number[] = [];
  for (let i = 4; i >= 0; i--) {
    labels.push(Math.round((maxValue.value / 4) * i));
  }
  return labels;
});

const getBarColor = (value: number): string => {
  const percentage = (value / maxValue.value) * 100;
  if (percentage >= 70) return '#22c55e';
  if (percentage >= 40) return '#fbbf24';
  return '#fc8181';
};
</script>

<style scoped>
.distribution-chart {
  width: 100%;
  height: 100%;
}

.chart-svg {
  width: 100%;
  height: 100%;
}

.bar {
  transition: all 0.3s;
  cursor: pointer;
}

.bar:hover {
  opacity: 0.8;
  transform: translateY(-2px);
}
</style>

