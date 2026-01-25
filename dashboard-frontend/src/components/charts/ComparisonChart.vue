<template>
  <div class="comparison-chart">
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
      
      <!-- Grouped bars -->
      <g v-for="(group, groupIndex) in groupedBars" :key="`group-${groupIndex}`">
        <g v-for="(bar, barIndex) in group.bars" :key="`bar-${groupIndex}-${barIndex}`">
          <rect
            :x="bar.x"
            :y="bar.y"
            :width="bar.width"
            :height="bar.height"
            :fill="bar.color"
            rx="4"
            class="bar"
          />
          <text
            :x="bar.x + bar.width / 2"
            :y="bar.y - 5"
            text-anchor="middle"
            fill="#ffffff"
            font-size="10"
            font-weight="600"
          >
            {{ bar.value }}
          </text>
        </g>
        <text
          :x="group.x + group.width / 2"
          :y="height - padding + 20"
          text-anchor="middle"
          fill="#a0aec0"
          font-size="10"
        >
          {{ group.label }}
        </text>
      </g>
      
      <!-- Legend -->
      <g class="legend">
        <rect
          v-for="(item, index) in legendItems"
          :key="`legend-${index}`"
          :x="width - padding - 120"
          :y="padding + index * 20"
          width="12"
          height="12"
          :fill="item.color"
          rx="2"
        />
        <text
          v-for="(item, index) in legendItems"
          :key="`legend-text-${index}`"
          :x="width - padding - 105"
          :y="padding + index * 20 + 9"
          fill="#a0aec0"
          font-size="11"
        >
          {{ item.label }}
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
  data: Array<{
    name: string;
    applications: Record<string, number>;
    teams: Record<string, number>;
  }>;
  height?: number;
}

const props = withDefaults(defineProps<Props>(), {
  height: 300
});

const width = 800;
const padding = 40;
const chartHeight = computed(() => props.height - padding * 2);

const colors = ['#4facfe', '#00f2fe', '#22c55e', '#fbbf24', '#fc8181', '#a855f7', '#ec4899'];

const allKeys = computed(() => {
  const keys = new Set<string>();
  props.data.forEach(item => {
    Object.keys(item.applications).forEach(k => keys.add(k));
    Object.keys(item.teams).forEach(k => keys.add(k));
  });
  return Array.from(keys);
});

const maxValue = computed(() => {
  let max = 0;
  props.data.forEach(item => {
    Object.values(item.applications).forEach(v => { if (v > max) max = v; });
    Object.values(item.teams).forEach(v => { if (v > max) max = v; });
  });
  return max || 100;
});

const groupedBars = computed(() => {
  if (props.data.length === 0) return [];
  
  const groupWidth = (width - padding * 2) / props.data.length;
  const barWidth = (groupWidth - 20) / (allKeys.value.length || 1);
  const maxBarHeight = chartHeight.value;
  
  return props.data.map((item, groupIndex) => {
    const groupX = padding + groupIndex * groupWidth;
    const bars: Array<{
      x: number;
      y: number;
      width: number;
      height: number;
      value: number;
      color: string;
    }> = [];
    
    let barIndex = 0;
    Object.entries(item.applications).forEach(([key, value]) => {
      const x = groupX + 10 + barIndex * barWidth;
      const height = (value / maxValue.value) * maxBarHeight;
      const y = padding + maxBarHeight - height;
      
      bars.push({
        x,
        y,
        width: barWidth - 4,
        height,
        value,
        color: colors[barIndex % colors.length]
      });
      barIndex++;
    });
    
    return {
      x: groupX,
      width: groupWidth,
      label: item.name,
      bars
    };
  });
});

const legendItems = computed(() => {
  return allKeys.value.map((key, index) => ({
    label: key,
    color: colors[index % colors.length]
  }));
});

const yAxisLabels = computed(() => {
  const labels: number[] = [];
  for (let i = 4; i >= 0; i--) {
    labels.push(Math.round((maxValue.value / 4) * i));
  }
  return labels;
});
</script>

<style scoped>
.comparison-chart {
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

