<template>
  <div class="domain-trend-chart">
    <div v-if="loading" class="chart-loading">Loading chart data...</div>
    <div v-else-if="error" class="chart-error">{{ error }}</div>
    <div v-else-if="data.length === 0" class="chart-empty">No data available for {{ domain }}</div>
    <svg v-else :viewBox="`0 0 ${width} ${height}`" class="chart-svg" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient :id="`lineGradient-${domainId}`" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" :style="`stop-color:${domainColor};stop-opacity:0.3`" />
          <stop offset="100%" :style="`stop-color:${domainColor};stop-opacity:0`" />
        </linearGradient>
      </defs>
      
      <!-- Y-axis labels -->
      <g class="y-axis">
        <text
          v-for="(label, i) in yAxisLabels"
          :key="i"
          :x="10"
          :y="padding + (i * (chartHeight / (yAxisLabels.length - 1)))"
          class="axis-label"
        >
          {{ label }}%
        </text>
      </g>

      <!-- X-axis labels -->
      <g class="x-axis">
        <text
          v-for="(point, i) in visiblePoints"
          :key="i"
          :x="padding + (i * xStep)"
          :y="height - 10"
          class="axis-label"
          v-if="i % Math.ceil(visiblePoints.length / 6) === 0"
        >
          {{ formatDate(point.date) }}
        </text>
      </g>

      <!-- Area fill -->
      <path
        :d="areaPath"
        :fill="`url(#lineGradient-${domainId})`"
        class="area-fill"
      />

      <!-- Line -->
      <path
        :d="linePath"
        fill="none"
        :stroke="domainColor"
        stroke-width="2"
        class="line"
      />

      <!-- Data points -->
      <circle
        v-for="(point, i) in visiblePoints"
        :key="i"
        :cx="padding + (i * xStep)"
        :cy="padding + chartHeight - (point.score / 100 * chartHeight)"
        r="4"
        :fill="domainColor"
        class="data-point"
        @mouseenter="showTooltip(point, $event)"
        @mouseleave="hideTooltip"
      />
    </svg>
    <div v-if="tooltip.visible" class="tooltip" :style="{ left: tooltip.x + 'px', top: tooltip.y + 'px' }">
      <div class="tooltip-date">{{ formatDate(tooltip.date) }}</div>
      <div class="tooltip-score">{{ tooltip.score }}%</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import axios from 'axios';

interface Props {
  domain: string;
  applicationId?: string;
  days?: number;
}

const props = withDefaults(defineProps<Props>(), {
  days: 30,
});

const loading = ref(false);
const error = ref<string | null>(null);
const data = ref<Array<{ date: string; score: number }>>([]);
const tooltip = ref({ visible: false, x: 0, y: 0, date: '', score: 0 });

const width = 800;
const height = 300;
const padding = 50;
const chartHeight = height - (padding * 2);

const domainId = computed(() => props.domain.toLowerCase().replace(/\s+/g, '-'));

const domainColor = computed(() => {
  const colors: Record<string, string> = {
    'data-contracts': '#4facfe',
    'iam': '#00f2fe',
    'api-security': '#43e97b',
  };
  return colors[domainId.value] || '#4facfe';
});

const yAxisLabels = computed(() => [100, 75, 50, 25, 0]);

const visiblePoints = computed(() => {
  return data.value.slice(-30); // Show last 30 points
});

const xStep = computed(() => {
  if (visiblePoints.value.length <= 1) return 0;
  return (width - (padding * 2)) / (visiblePoints.value.length - 1);
});

const linePath = computed(() => {
  if (visiblePoints.value.length === 0) return '';
  const points = visiblePoints.value.map((point, i) => {
    const x = padding + (i * xStep.value);
    const y = padding + chartHeight - (point.score / 100 * chartHeight);
    return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
  });
  return points.join(' ');
});

const areaPath = computed(() => {
  if (visiblePoints.value.length === 0) return '';
  const line = linePath.value;
  const firstPoint = visiblePoints.value[0];
  const lastPoint = visiblePoints.value[visiblePoints.value.length - 1];
  const firstX = padding;
  const firstY = padding + chartHeight;
  const lastX = padding + ((visiblePoints.value.length - 1) * xStep.value);
  const lastY = padding + chartHeight;
  return `${line} L ${lastX} ${lastY} L ${firstX} ${firstY} Z`;
});

const fetchData = async () => {
  loading.value = true;
  error.value = null;
  try {
    const params: Record<string, any> = {
      days: props.days,
      domain: props.domain,
    };
    if (props.applicationId) {
      params.applicationId = props.applicationId;
    }
    const response = await axios.get('/api/v1/compliance-scores/history', { params });
    data.value = (response.data || []).sort((a: any, b: any) => 
      new Date(a.date).getTime() - new Date(b.date).getTime()
    );
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load trend data';
    console.error('Error fetching domain trend data:', err);
  } finally {
    loading.value = false;
  }
};

const formatDate = (dateString: string) => {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const showTooltip = (point: { date: string; score: number }, event: MouseEvent) => {
  tooltip.value = {
    visible: true,
    x: event.clientX,
    y: event.clientY,
    date: point.date,
    score: point.score,
  };
};

const hideTooltip = () => {
  tooltip.value.visible = false;
};

onMounted(fetchData);
watch(() => [props.applicationId, props.days, props.domain], fetchData);
</script>

<style scoped>
.domain-trend-chart {
  width: 100%;
  background: var(--color-bg-overlay-dark);
  opacity: 0.6;
  border: var(--border-width-thin) solid var(--border-color-primary);
  opacity: 0.2;
  border-radius: var(--border-radius-md);
  padding: var(--spacing-lg);
  box-sizing: border-box;
}

.chart-svg {
  width: 100%;
  height: auto;
  min-width: 600px;
}

.axis-label {
  font-size: var(--font-size-xs);
  fill: var(--color-text-secondary);
}

.area-fill {
  opacity: 0.3;
}

.line {
  stroke-linecap: round;
  stroke-linejoin: round;
}

.data-point {
  cursor: pointer;
  transition: r 0.2s;
}

.data-point:hover {
  r: 6;
}

.tooltip {
  position: fixed;
  background: var(--color-bg-overlay-dark);
  opacity: 0.95;
  border: var(--border-width-thin) solid var(--border-color-primary-active);
  border-radius: var(--border-radius-sm);
  padding: var(--spacing-sm) var(--spacing-sm);
  pointer-events: none;
  z-index: 1000;
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
}

.tooltip-date {
  font-weight: var(--font-weight-semibold);
  margin-bottom: var(--spacing-xs);
}

.tooltip-score {
  color: var(--color-primary);
  font-weight: var(--font-weight-semibold);
}

.chart-loading,
.chart-error,
.chart-empty {
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}
</style>

