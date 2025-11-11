<template>
  <div class="line-chart">
    <svg :viewBox="`0 0 ${width} ${height}`" class="chart-svg" preserveAspectRatio="none">
      <defs>
        <linearGradient :id="gradientId" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" :style="`stop-color:${color};stop-opacity:0.3`" />
          <stop offset="100%" :style="`stop-color:${color};stop-opacity:0`" />
        </linearGradient>
      </defs>
      
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
      
      <!-- Data line -->
      <polyline
        v-if="points.length > 0"
        :points="pointsString"
        :fill="`url(#${gradientId})`"
        :stroke="color"
        stroke-width="2"
        class="data-line"
      />
      
      <!-- Data points -->
      <circle
        v-for="(point, index) in points"
        :key="`point-${index}`"
        :cx="point.x"
        :cy="point.y"
        r="4"
        :fill="color"
        class="data-point"
      />
      
      <!-- X-axis labels -->
      <text
        v-for="(point, index) in xAxisLabels"
        :key="`xlabel-${index}`"
        :x="point.x"
        :y="height - padding + 20"
        text-anchor="middle"
        fill="#a0aec0"
        font-size="10"
      >
        {{ point.label }}
      </text>
    </svg>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Props {
  data: Array<{ date: string; value: number }>;
  height?: number;
  color?: string;
}

const props = withDefaults(defineProps<Props>(), {
  height: 250,
  color: '#4facfe'
});

const width = 600;
const padding = 40;
const chartHeight = computed(() => props.height - padding * 2);

const gradientId = computed(() => `gradient-${Math.random().toString(36).substr(2, 9)}`);

const minValue = computed(() => {
  if (props.data.length === 0) return 0;
  return Math.min(...props.data.map(d => d.value));
});

const maxValue = computed(() => {
  if (props.data.length === 0) return 100;
  return Math.max(...props.data.map(d => d.value));
});

const valueRange = computed(() => maxValue.value - minValue.value || 1);

const points = computed(() => {
  if (props.data.length === 0) return [];
  
  const stepX = (width - padding * 2) / (props.data.length - 1 || 1);
  
  return props.data.map((item, index) => {
    const x = padding + index * stepX;
    const normalizedValue = (item.value - minValue.value) / valueRange.value;
    const y = padding + chartHeight.value - (normalizedValue * chartHeight.value);
    return { x, y, value: item.value, date: item.date };
  });
});

const pointsString = computed(() => {
  if (points.value.length === 0) return '';
  return points.value.map(p => `${p.x},${p.y}`).join(' ');
});

const xAxisLabels = computed(() => {
  if (props.data.length === 0) return [];
  const step = Math.max(1, Math.floor(props.data.length / 5));
  return points.value
    .filter((_, index) => index % step === 0 || index === props.data.length - 1)
    .map((point, index) => {
      const dataIndex = points.value.indexOf(point);
      const date = props.data[dataIndex]?.date || '';
      const label = date ? new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '';
      return { x: point.x, label };
    });
});
</script>

<style scoped>
.line-chart {
  width: 100%;
  height: 100%;
}

.chart-svg {
  width: 100%;
  height: 100%;
}

.data-line {
  transition: all 0.3s;
}

.data-point {
  transition: all 0.3s;
  cursor: pointer;
}

.data-point:hover {
  r: 6;
  opacity: 0.8;
}
</style>

