<template>
  <div class="trends-chart">
    <div class="chart-container">
      <svg :width="width" :height="height" class="chart-svg">
        <!-- Grid lines -->
        <g class="grid-lines">
          <line
            v-for="(tick, index) in yTicks"
            :key="`grid-${index}`"
            :x1="padding"
            :y1="tick.y"
            :x2="width - padding"
            :y2="tick.y"
            stroke="rgba(79, 172, 254, 0.1)"
            stroke-width="1"
          />
        </g>

        <!-- Y-axis labels -->
        <g class="y-labels">
          <text
            v-for="(tick, index) in yTicks"
            :key="`y-label-${index}`"
            :x="padding - 8"
            :y="tick.y + 4"
            text-anchor="end"
            fill="#a0aec0"
            font-size="12"
          >
            {{ tick.value }}
          </text>
        </g>

        <!-- X-axis labels -->
        <g class="x-labels">
          <text
            v-for="(point, index) in chartPoints"
            :key="`x-label-${index}`"
            :x="point.x"
            :y="height - padding + 20"
            text-anchor="middle"
            fill="#a0aec0"
            font-size="11"
          >
            {{ formatDateLabel(point.date) }}
          </text>
        </g>

        <!-- Area under line -->
        <path
          :d="areaPath"
          fill="url(#gradient)"
          opacity="0.3"
        />

        <!-- Line -->
        <path
          :d="linePath"
          fill="none"
          stroke="#4facfe"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        />

        <!-- Data points -->
        <circle
          v-for="(point, index) in chartPoints"
          :key="`point-${index}`"
          :cx="point.x"
          :cy="point.y"
          r="4"
          fill="#4facfe"
          stroke="#0f1419"
          stroke-width="2"
        />
      </svg>

      <!-- Gradient definition -->
      <defs>
        <linearGradient id="gradient" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.3" />
          <stop offset="100%" style="stop-color:#4facfe;stop-opacity:0" />
        </linearGradient>
      </defs>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  trends: Array<{ date: string; score: number }>;
}>();

const width = 800;
const height = 300;
const padding = 60;

const minScore = 0;
const maxScore = 100;

const chartPoints = computed(() => {
  if (props.trends.length === 0) return [];

  const xStep = (width - padding * 2) / Math.max(1, props.trends.length - 1);
  const yRange = maxScore - minScore;

  return props.trends.map((trend, index) => {
    const x = padding + index * xStep;
    const normalizedScore = (trend.score - minScore) / yRange;
    const y = height - padding - normalizedScore * (height - padding * 2);

    return {
      x,
      y,
      date: trend.date,
      score: trend.score,
    };
  });
});

const yTicks = computed(() => {
  const tickCount = 5;
  const yRange = maxScore - minScore;
  const tickStep = yRange / (tickCount - 1);
  const yStep = (height - padding * 2) / (tickCount - 1);

  return Array.from({ length: tickCount }, (_, i) => {
    const value = maxScore - i * tickStep;
    const y = padding + i * yStep;
    return { value: Math.round(value), y };
  });
});

const linePath = computed(() => {
  if (chartPoints.value.length === 0) return '';

  const points = chartPoints.value;
  let path = `M ${points[0].x} ${points[0].y}`;

  for (let i = 1; i < points.length; i++) {
    path += ` L ${points[i].x} ${points[i].y}`;
  }

  return path;
});

const areaPath = computed(() => {
  if (chartPoints.value.length === 0) return '';

  const points = chartPoints.value;
  const bottomY = height - padding;

  let path = `M ${points[0].x} ${bottomY}`;
  path += ` L ${points[0].x} ${points[0].y}`;

  for (let i = 1; i < points.length; i++) {
    path += ` L ${points[i].x} ${points[i].y}`;
  }

  path += ` L ${points[points.length - 1].x} ${bottomY}`;
  path += ' Z';

  return path;
});

const formatDateLabel = (date: string) => {
  const d = new Date(date);
  const month = d.toLocaleDateString('en-US', { month: 'short' });
  const day = d.getDate();
  return `${month} ${day}`;
};
</script>

<style scoped>
.trends-chart {
  width: 100%;
}

.chart-container {
  width: 100%;
  overflow-x: auto;
}

.chart-svg {
  display: block;
  width: 100%;
  height: auto;
}
</style>

