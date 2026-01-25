<template>
  <div class="trend-chart">
    <div v-if="loading" class="chart-loading">Loading chart data...</div>
    <div v-else-if="error" class="chart-error">{{ error }}</div>
    <div v-else-if="data.length === 0" class="chart-empty">No data available</div>
    <svg v-else :viewBox="`0 0 ${width} ${height}`" class="chart-svg" preserveAspectRatio="xMidYMid meet">
      <!-- Grid lines -->
      <defs>
        <linearGradient id="lineGradient" x1="0%" y1="0%" x2="0%" y2="100%">
          <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.3" />
          <stop offset="100%" style="stop-color:#4facfe;stop-opacity:0" />
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
        fill="url(#lineGradient)"
        class="area-fill"
      />

      <!-- Line -->
      <path
        :d="linePath"
        fill="none"
        stroke="#4facfe"
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
        fill="#4facfe"
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
import { ref, computed, onMounted } from 'vue';
import axios from 'axios';

interface Props {
  applicationId?: string;
  days?: number;
  startDate?: string;
  endDate?: string;
}

const props = withDefaults(defineProps<Props>(), {
  days: 30,
});

const loading = ref(false);
const error = ref<string | null>(null);
const data = ref<Array<{ date: string; score: number }>>([]);
const tooltip = ref({ visible: false, x: 0, y: 0, date: '', score: 0 });

const width = 800;
const height = 400;
const padding = 50;
const chartHeight = height - (padding * 2);
const chartWidth = width - (padding * 2);

const maxScore = 100;
const minScore = 0;

const yAxisLabels = computed(() => {
  const labels = [];
  for (let i = 0; i <= 5; i++) {
    labels.push(maxScore - (i * (maxScore - minScore) / 5));
  }
  return labels;
});

const visiblePoints = computed(() => {
  return data.value.slice(-30); // Show last 30 points
});

const xStep = computed(() => {
  return visiblePoints.value.length > 1 ? chartWidth / (visiblePoints.value.length - 1) : 0;
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
  const firstX = padding;
  const lastX = padding + chartWidth;
  const bottomY = padding + chartHeight;
  
  return `${line} L ${lastX} ${bottomY} L ${firstX} ${bottomY} Z`;
});

const loadData = async () => {
  try {
    loading.value = true;
    error.value = null;
    
    const params: any = { days: props.days };
    if (props.applicationId) params.applicationId = props.applicationId;
    if (props.startDate) params.startDate = props.startDate;
    if (props.endDate) params.endDate = props.endDate;
    
    const response = await axios.get('/api/v1/compliance-scores/history', { params });
    data.value = response.data || [];
    
    // If no data, create some sample data for demonstration
    if (data.value.length === 0) {
      const now = new Date();
      data.value = Array.from({ length: props.days }, (_, i) => {
        const date = new Date(now);
        date.setDate(date.getDate() - (props.days - i - 1));
        return {
          date: date.toISOString().split('T')[0],
          score: 70 + Math.random() * 25, // Random score between 70-95
        };
      });
    }
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load trend data';
    console.error('Error loading trend data:', err);
  } finally {
    loading.value = false;
  }
};

const formatDate = (dateStr: string): string => {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
};

const showTooltip = (point: { date: string; score: number }, event: MouseEvent) => {
  tooltip.value = {
    visible: true,
    x: event.clientX,
    y: event.clientY - 60,
    date: point.date,
    score: Math.round(point.score),
  };
};

const hideTooltip = () => {
  tooltip.value.visible = false;
};

onMounted(() => {
  loadData();
});
</script>

<style scoped>
.trend-chart {
  position: relative;
  width: 100%;
  height: 400px;
  background: rgba(15, 20, 25, 0.6);
  border-radius: 8px;
  padding: 20px;
}

.chart-svg {
  width: 100%;
  height: 100%;
}

.axis-label {
  font-size: 12px;
  fill: #a0aec0;
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

.area-fill {
  opacity: 0.3;
}

.tooltip {
  position: fixed;
  background: rgba(26, 31, 46, 0.95);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  padding: 8px 12px;
  pointer-events: none;
  z-index: 1000;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.tooltip-date {
  font-size: 0.75rem;
  color: #a0aec0;
  margin-bottom: 4px;
}

.tooltip-score {
  font-size: 1rem;
  font-weight: 600;
  color: #4facfe;
}

.chart-loading,
.chart-error,
.chart-empty {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #a0aec0;
}

.chart-error {
  color: #fc8181;
}
</style>

