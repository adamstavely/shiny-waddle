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
        @mouseenter="handlePointHover(point, $event)"
        @mouseleave="handlePointLeave"
        @click="handlePointClick(point)"
        role="button"
        :aria-label="`Data point ${index + 1}: ${point.value} on ${point.date}`"
        tabindex="0"
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
    
    <!-- Tooltip -->
    <div
      v-if="hoveredPoint"
      class="chart-tooltip"
      :style="tooltipStyle"
    >
      <div class="tooltip-header">
        <strong>{{ formatDate(hoveredPoint.date) }}</strong>
      </div>
      <div class="tooltip-value">
        Value: <strong>{{ hoveredPoint.value.toFixed(2) }}</strong>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onBeforeUnmount } from 'vue';

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

const emit = defineEmits<{
  pointClick: [point: { x: number; y: number; value: number; date: string }];
}>();

const hoveredPoint = ref<{ x: number; y: number; value: number; date: string } | null>(null);
const tooltipStyle = ref<{ top: string; left: string }>({ top: '0px', left: '0px' });

const handlePointHover = (point: { x: number; y: number; value: number; date: string }, event: MouseEvent) => {
  hoveredPoint.value = point;
  updateTooltipPosition(event);
};

const handlePointLeave = () => {
  hoveredPoint.value = null;
};

const handlePointClick = (point: { x: number; y: number; value: number; date: string }) => {
  emit('pointClick', point);
};

const formatDate = (date: string): string => {
  return new Date(date).toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric' 
  });
};

const updateTooltipPosition = (event: MouseEvent) => {
  const rect = (event.currentTarget as HTMLElement).closest('.line-chart')?.getBoundingClientRect();
  if (!rect) return;
  
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  
  tooltipStyle.value = {
    top: `${y - 50}px`,
    left: `${x + 10}px`,
  };
};

const handleMouseMove = (event: MouseEvent) => {
  if (hoveredPoint.value) {
    updateTooltipPosition(event);
  }
};

onMounted(() => {
  document.addEventListener('mousemove', handleMouseMove);
});

onBeforeUnmount(() => {
  document.removeEventListener('mousemove', handleMouseMove);
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

.chart-tooltip {
  position: absolute;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  padding: 12px;
  pointer-events: none;
  z-index: 1000;
  min-width: 150px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}

.tooltip-header {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
  margin-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  padding-bottom: 8px;
}

.tooltip-value {
  font-size: 0.8rem;
  color: #a0aec0;
}

.tooltip-value strong {
  color: #ffffff;
  font-weight: 600;
}
</style>

