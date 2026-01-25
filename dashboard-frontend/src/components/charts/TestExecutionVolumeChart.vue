<template>
  <div class="test-execution-volume-chart">
    <div v-if="!data || data.length === 0" class="chart-empty">
      <p>No volume data available</p>
    </div>
    <div v-else class="chart-wrapper" @mousemove="handleMouseMove" @mouseleave="hoveredIndex = null">
      <svg :width="width" :height="height" class="chart-svg">
        <!-- Grid lines -->
        <defs>
          <linearGradient id="barGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.8 }" />
            <stop offset="100%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.4 }" />
          </linearGradient>
        </defs>
        
        <!-- Y-axis labels -->
        <g class="y-axis">
          <text
            v-for="(label, index) in yAxisLabels"
            :key="index"
            :x="10"
            :y="padding + (height - 2 * padding) * (1 - index / (yAxisLabels.length - 1))"
            class="axis-label"
          >
            {{ label }}
          </text>
        </g>

        <!-- X-axis labels -->
        <g class="x-axis">
          <text
            v-for="(point, index) in dataPoints"
            :key="index"
            :x="getBarX(index) + barWidth / 2"
            :y="height - 10"
            class="axis-label"
            text-anchor="middle"
          >
            {{ formatPeriod(point.period) }}
          </text>
        </g>

        <!-- Bars -->
        <rect
          v-for="(point, index) in dataPoints"
          :key="index"
          :x="getBarX(index)"
          :y="padding + (height - 2 * padding) * (1 - point.normalizedValue)"
          :width="barWidth"
          :height="(height - 2 * padding) * point.normalizedValue"
          fill="url(#barGradient)"
          class="bar"
          @mouseenter="hoveredIndex = index"
          @mouseleave="hoveredIndex = null"
        />

        <!-- Hover indicator line -->
        <line
          v-if="hoveredIndex !== null"
          :x1="getBarX(hoveredIndex) + barWidth / 2"
          :y1="padding"
          :x2="getBarX(hoveredIndex) + barWidth / 2"
          :y2="height - padding"
          stroke="#4facfe"
          stroke-width="2"
          stroke-dasharray="4,4"
          opacity="0.5"
        />
      </svg>

      <!-- Tooltip -->
      <div
        v-if="hoveredIndex !== null && dataPoints[hoveredIndex]"
        class="chart-tooltip"
        :style="tooltipStyle"
      >
        <div class="tooltip-period">{{ dataPoints[hoveredIndex].period }}</div>
        <div class="tooltip-value">Tests: {{ dataPoints[hoveredIndex].totalTests }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';

interface VolumeDataPoint {
  period: string;
  totalTests: number;
}

interface Props {
  data: VolumeDataPoint[];
  period?: 'day' | 'week' | 'month';
}

const props = withDefaults(defineProps<Props>(), {
  period: 'day',
});

const width = 800;
const height = 300;
const padding = 40;

const barWidth = computed(() => {
  if (!props.data || props.data.length === 0) return 30;
  const availableWidth = width - 2 * padding;
  const calculatedWidth = availableWidth / props.data.length - 4; // 4px gap between bars
  return Math.max(20, Math.min(50, calculatedWidth)); // Min 20px, max 50px
});

const hoveredIndex = ref<number | null>(null);
const tooltipStyle = ref({ left: '0px', top: '0px' });

const dataPoints = computed(() => {
  if (!props.data || props.data.length === 0) return [];
  
  const maxValue = Math.max(...props.data.map(d => d.totalTests), 1);
  
  return props.data.map(d => ({
    ...d,
    normalizedValue: d.totalTests / maxValue,
  }));
});

const yAxisLabels = computed(() => {
  if (dataPoints.value.length === 0) return [0, 1, 2, 3, 4, 5];
  
  const maxValue = Math.max(...props.data.map(d => d.totalTests), 1);
  const step = Math.ceil(maxValue / 5);
  const labels: number[] = [];
  
  for (let i = 0; i <= 5; i++) {
    labels.push(i * step);
  }
  
  return labels;
});

const getBarX = (index: number) => {
  if (dataPoints.value.length === 0) return padding;
  const availableWidth = width - 2 * padding;
  const barSpacing = availableWidth / dataPoints.value.length;
  return padding + (index * barSpacing) + (barSpacing - barWidth.value) / 2;
};

const formatPeriod = (period: string) => {
  // Format date strings or week/month identifiers
  if (period.includes('-W')) {
    // Week format: 2024-W03
    return period.split('-W')[1];
  }
  if (period.match(/^\d{4}-\d{2}$/)) {
    // Month format: 2024-01
    const [year, month] = period.split('-');
    const date = new Date(parseInt(year), parseInt(month) - 1);
    return date.toLocaleDateString('en-US', { month: 'short' });
  }
  // Day format: 2024-01-15
  if (period.match(/^\d{4}-\d{2}-\d{2}$/)) {
    const date = new Date(period);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }
  return period;
};

const handleMouseMove = (event: MouseEvent) => {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
  const x = event.clientX - rect.left;
  
  // Find which bar the mouse is over
  let foundIndex: number | null = null;
  for (let i = 0; i < dataPoints.value.length; i++) {
    const barX = getBarX(i);
    if (x >= barX && x <= barX + barWidth.value) {
      foundIndex = i;
      break;
    }
  }
  
  if (foundIndex !== null) {
    hoveredIndex.value = foundIndex;
    tooltipStyle.value = {
      left: `${event.clientX - rect.left}px`,
      top: `${event.clientY - rect.top - 60}px`,
    };
  } else {
    hoveredIndex.value = null;
  }
};
</script>

<style scoped>
.test-execution-volume-chart {
  width: 100%;
  height: 100%;
}

.chart-empty {
  padding: 3rem;
  text-align: center;
  color: #718096;
}

.chart-wrapper {
  position: relative;
  width: 100%;
  height: 300px;
}

.chart-svg {
  width: 100%;
  height: 100%;
}

.axis-label {
  font-size: 0.75rem;
  fill: #a0aec0;
}

.bar {
  cursor: pointer;
  transition: opacity 0.2s;
}

.bar:hover {
  opacity: 0.8;
}

.chart-tooltip {
  position: absolute;
  background: rgba(15, 20, 25, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  padding: 0.75rem;
  pointer-events: none;
  z-index: 1000;
  min-width: 150px;
}

.tooltip-period {
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.25rem;
}

.tooltip-value {
  color: #4facfe;
  font-size: 0.875rem;
}
</style>

