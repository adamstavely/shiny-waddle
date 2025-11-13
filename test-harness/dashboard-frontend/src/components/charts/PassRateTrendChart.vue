<template>
  <div class="pass-rate-trend-chart">
    <div v-if="!data || data.length === 0" class="chart-empty">
      <p>No trend data available</p>
    </div>
    <div v-else class="chart-wrapper">
      <svg :width="width" :height="height" class="chart-svg">
        <!-- Grid lines -->
        <defs>
          <linearGradient id="lineGradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.8" />
            <stop offset="100%" style="stop-color:#4facfe;stop-opacity:0.2" />
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
            {{ label }}%
          </text>
        </g>

        <!-- X-axis labels -->
        <g class="x-axis">
          <text
            v-for="(point, index) in dataPoints"
            :key="index"
            :x="padding + (width - 2 * padding) * (index / (dataPoints.length - 1 || 1))"
            :y="height - 10"
            class="axis-label"
            text-anchor="middle"
          >
            {{ formatPeriod(point.period) }}
          </text>
        </g>

        <!-- Area under line -->
        <path
          :d="areaPath"
          fill="url(#lineGradient)"
          class="area-path"
        />

        <!-- Line -->
        <path
          :d="linePath"
          fill="none"
          stroke="#4facfe"
          stroke-width="2"
          class="line-path"
        />

        <!-- Data points -->
        <circle
          v-for="(point, index) in dataPoints"
          :key="index"
          :cx="padding + (width - 2 * padding) * (index / (dataPoints.length - 1 || 1))"
          :cy="padding + (height - 2 * padding) * (1 - point.passRate / 100)"
          r="4"
          fill="#4facfe"
          class="data-point"
        />

        <!-- Tooltip line -->
        <line
          v-if="hoveredIndex !== null"
          :x1="padding + (width - 2 * padding) * (hoveredIndex / (dataPoints.length - 1 || 1))"
          :y1="padding"
          :x2="padding + (width - 2 * padding) * (hoveredIndex / (dataPoints.length - 1 || 1))"
          :y2="height - padding"
          stroke="#4facfe"
          stroke-width="1"
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
        <div class="tooltip-value">Pass Rate: {{ dataPoints[hoveredIndex].passRate.toFixed(1) }}%</div>
        <div class="tooltip-tests">Tests: {{ dataPoints[hoveredIndex].totalTests }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';

interface TrendDataPoint {
  period: string;
  passRate: number;
  totalTests: number;
}

const props = defineProps<{
  data: TrendDataPoint[];
}>();

const width = 800;
const height = 300;
const padding = 40;

const hoveredIndex = ref<number | null>(null);
const tooltipStyle = ref({ left: '0px', top: '0px' });

const dataPoints = computed(() => {
  if (!props.data || props.data.length === 0) return [];
  return props.data.map(d => ({
    ...d,
    passRate: Math.max(0, Math.min(100, d.passRate)), // Clamp between 0-100
  }));
});

const yAxisLabels = computed(() => {
  return [0, 25, 50, 75, 100];
});

const linePath = computed(() => {
  if (dataPoints.value.length === 0) return '';
  
  const points = dataPoints.value.map((point, index) => {
    const x = padding + (width - 2 * padding) * (index / (dataPoints.value.length - 1 || 1));
    const y = padding + (height - 2 * padding) * (1 - point.passRate / 100);
    return `${index === 0 ? 'M' : 'L'} ${x} ${y}`;
  });
  
  return points.join(' ');
});

const areaPath = computed(() => {
  if (dataPoints.value.length === 0) return '';
  
  const line = linePath.value;
  const firstX = padding;
  const lastX = width - padding;
  const baselineY = height - padding;
  
  return `${line} L ${lastX} ${baselineY} L ${firstX} ${baselineY} Z`;
});

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
  const index = Math.round(((x - padding) / (width - 2 * padding)) * (dataPoints.value.length - 1));
  
  if (index >= 0 && index < dataPoints.value.length) {
    hoveredIndex.value = index;
    tooltipStyle.value = {
      left: `${event.clientX - rect.left}px`,
      top: `${event.clientY - rect.top - 60}px`,
    };
  } else {
    hoveredIndex.value = null;
  }
};

const handleMouseLeave = () => {
  hoveredIndex.value = null;
};

onMounted(() => {
  // Add mouse event listeners if needed
});

onUnmounted(() => {
  // Cleanup if needed
});
</script>

<style scoped>
.pass-rate-trend-chart {
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

.line-path {
  stroke-linecap: round;
  stroke-linejoin: round;
}

.area-path {
  opacity: 0.3;
}

.data-point {
  cursor: pointer;
  transition: r 0.2s;
}

.data-point:hover {
  r: 6;
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
  margin-bottom: 0.25rem;
}

.tooltip-tests {
  color: #a0aec0;
  font-size: 0.75rem;
}
</style>

