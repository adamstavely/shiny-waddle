<template>
  <div class="compliance-score-gauge">
    <svg :width="size" :height="size / 2 + 40" class="gauge-svg">
      <!-- Background arc -->
      <path
        :d="backgroundArc"
        fill="none"
        stroke="#2d3748"
        stroke-width="20"
        class="background-arc"
      />
      
      <!-- Score arc -->
      <path
        :d="scoreArc"
        fill="none"
        :stroke="scoreColor"
        stroke-width="20"
        stroke-linecap="round"
        class="score-arc"
      />
      
      <!-- Score text -->
      <text
        :x="size / 2"
        :y="size / 2 + 20"
        text-anchor="middle"
        class="score-text"
      >
        {{ score.toFixed(1) }}%
      </text>
      
      <!-- Trend indicator -->
      <g v-if="trend" :transform="`translate(${size / 2}, ${size / 2 - 20})`">
        <component
          :is="trendIcon"
          :class="['trend-icon', `trend-${trend}`]"
          :size="20"
        />
      </g>
    </svg>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { ArrowUp, ArrowDown, Minus } from 'lucide-vue-next';

interface Props {
  score: number;
  trend?: 'improving' | 'declining' | 'stable';
}

const props = withDefaults(defineProps<Props>(), {
  trend: 'stable',
});

const size = 200;
const radius = 80;
const centerX = size / 2;
const centerY = size / 2;

const scoreColor = computed(() => {
  if (props.score >= 90) return '#48bb78';
  if (props.score >= 70) return '#4facfe';
  if (props.score >= 50) return '#ed8936';
  return '#fc8181';
});

const backgroundArc = computed(() => {
  const startAngle = Math.PI;
  const endAngle = 0;
  return describeArc(centerX, centerY, radius, startAngle, endAngle);
});

const scoreArc = computed(() => {
  const startAngle = Math.PI;
  const endAngle = Math.PI - (props.score / 100) * Math.PI;
  return describeArc(centerX, centerY, radius, startAngle, endAngle);
});

const trendIcon = computed(() => {
  if (props.trend === 'improving') return ArrowUp;
  if (props.trend === 'declining') return ArrowDown;
  return Minus;
});

function describeArc(x: number, y: number, radius: number, startAngle: number, endAngle: number): string {
  const start = polarToCartesian(x, y, radius, endAngle);
  const end = polarToCartesian(x, y, radius, startAngle);
  const largeArcFlag = endAngle - startAngle <= Math.PI ? '0' : '1';
  return ['M', start.x, start.y, 'A', radius, radius, 0, largeArcFlag, 0, end.x, end.y].join(' ');
}

function polarToCartesian(centerX: number, centerY: number, radius: number, angleInRadians: number) {
  return {
    x: centerX + radius * Math.cos(angleInRadians),
    y: centerY + radius * Math.sin(angleInRadians),
  };
}
</script>

<style scoped>
.compliance-score-gauge {
  display: flex;
  justify-content: center;
  align-items: center;
  padding: 2rem;
}

.gauge-svg {
  width: 200px;
  height: 140px;
}

.background-arc {
  opacity: 0.2;
}

.score-arc {
  transition: stroke 0.3s;
  filter: drop-shadow(0 0 4px currentColor);
}

.score-text {
  font-size: 2rem;
  font-weight: 700;
  fill: #ffffff;
}

.trend-icon {
  transition: color 0.3s;
}

.trend-improving {
  color: #48bb78;
}

.trend-declining {
  color: #fc8181;
}

.trend-stable {
  color: #a0aec0;
}
</style>

