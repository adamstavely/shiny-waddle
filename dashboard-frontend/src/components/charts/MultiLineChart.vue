<template>
  <div class="multi-line-chart">
    <svg :viewBox="`0 0 ${width} ${height}`" class="chart-svg" preserveAspectRatio="none">
      <defs>
        <linearGradient
          v-for="(color, index) in colors"
          :key="`gradient-${index}`"
          :id="`gradient-${index}-${gradientId}`"
          x1="0%"
          y1="0%"
          x2="0%"
          y2="100%"
        >
          <stop offset="0%" :style="`stop-color:${color};stop-opacity:0.2`" />
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
          :style="{ stroke: 'var(--border-color-muted)' }"
          stroke-width="1"
        />
      </g>
      
      <!-- Data lines -->
      <g v-for="(series, seriesIndex) in seriesData" :key="`series-${seriesIndex}`">
        <polyline
          :points="series.pointsString"
          :fill="`url(#gradient-${seriesIndex}-${gradientId})`"
          :stroke="series.color"
          stroke-width="2"
          class="data-line"
        />
        <circle
          v-for="(point, pointIndex) in series.points"
          :key="`point-${seriesIndex}-${pointIndex}`"
          :cx="point.x"
          :cy="point.y"
          r="3"
          :fill="series.color"
          class="data-point"
        />
      </g>
      
      <!-- Legend -->
      <g class="legend">
        <rect
          v-for="(series, index) in seriesData"
          :key="`legend-${index}`"
          :x="width - padding - 150"
          :y="padding + index * 20"
          width="12"
          height="12"
          :fill="series.color"
          rx="2"
        />
        <text
          v-for="(series, index) in seriesData"
          :key="`legend-text-${index}`"
          :x="width - padding - 135"
          :y="padding + index * 20 + 9"
          fill="#a0aec0"
          font-size="11"
        >
          {{ series.name }}
        </text>
      </g>
    </svg>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Props {
  data: Record<string, Array<{ date: string; value: number }>>;
  height?: number;
}

const props = withDefaults(defineProps<Props>(), {
  height: 250
});

const width = 600;
const padding = 40;
const chartHeight = computed(() => props.height - padding * 2);

const colors = ['#4facfe', '#00f2fe', '#22c55e', '#fbbf24', '#fc8181', '#a855f7', '#ec4899'];
const gradientId = computed(() => Math.random().toString(36).substr(2, 9));

const allDates = computed(() => {
  const dateSet = new Set<string>();
  Object.values(props.data).forEach(series => {
    series.forEach(item => dateSet.add(item.date));
  });
  return Array.from(dateSet).sort();
});

const minValue = computed(() => {
  let min = Infinity;
  Object.values(props.data).forEach(series => {
    series.forEach(item => {
      if (item.value < min) min = item.value;
    });
  });
  return min === Infinity ? 0 : min;
});

const maxValue = computed(() => {
  let max = -Infinity;
  Object.values(props.data).forEach(series => {
    series.forEach(item => {
      if (item.value > max) max = item.value;
    });
  });
  return max === -Infinity ? 100 : max;
});

const valueRange = computed(() => maxValue.value - minValue.value || 1);

const seriesData = computed(() => {
  return Object.entries(props.data).map(([name, series], index) => {
    const stepX = (width - padding * 2) / (allDates.value.length - 1 || 1);
    
    const points = allDates.value.map((date, dateIndex) => {
      const item = series.find(d => d.date === date);
      const value = item ? item.value : null;
      const x = padding + dateIndex * stepX;
      
      if (value === null) {
        return { x, y: null, value: null };
      }
      
      const normalizedValue = (value - minValue.value) / valueRange.value;
      const y = padding + chartHeight.value - (normalizedValue * chartHeight.value);
      return { x, y, value };
    });
    
    const pointsString = points
      .filter(p => p.y !== null)
      .map(p => `${p.x},${p.y}`)
      .join(' ');
    
    return {
      name,
      color: colors[index % colors.length],
      points,
      pointsString
    };
  });
});
</script>

<style scoped>
.multi-line-chart {
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
  r: 5;
  opacity: 0.8;
}
</style>

