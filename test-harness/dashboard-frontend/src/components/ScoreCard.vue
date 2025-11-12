<template>
  <div class="card">
    <h2>
      <component v-if="icon" :is="icon" class="title-icon" />
      {{ title }}
    </h2>
    <div v-if="Object.keys(scores).length === 0" class="empty">
      No data available
    </div>
    <div v-else>
      <div
        v-for="(scoreData, key) in scores"
        :key="key"
        class="metric"
        :class="{ clickable: isClickable }"
        @click="handleClick(key)"
      >
        <span class="metric-label">{{ key }}</span>
        <span class="metric-value">{{ scoreData.overallScore.toFixed(1) }}%</span>
        <ChevronRight v-if="isClickable" class="chevron-icon" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRouter } from 'vue-router';
import { ChevronRight, type LucideIcon } from 'lucide-vue-next';

const props = defineProps<{
  title: string;
  scores: Record<string, any>;
  type?: 'application' | 'team';
  icon?: LucideIcon;
}>();

const router = useRouter();

const isClickable = computed(() => {
  return props.type === 'application' || props.type === 'team';
});

const handleClick = (key: string) => {
  if (!isClickable.value) return;
  
  // Convert key to URL-friendly format
  const id = key.toLowerCase().replace(/\s+/g, '-');
  
  if (props.type === 'application') {
    router.push(`/dashboard/app/${id}`);
  } else if (props.type === 'team') {
    router.push(`/dashboard/team/${id}`);
  }
};
</script>

<style scoped>
.card {
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.card h2 {
  color: #ffffff;
  margin-bottom: 20px;
  font-size: 1.5em;
  border-bottom: 2px solid #4facfe;
  padding-bottom: 10px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 12px;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
  flex-shrink: 0;
}

.metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 15px 0;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  transition: all 0.2s;
}

.metric:last-child {
  border-bottom: none;
}

.metric.clickable {
  cursor: pointer;
  padding: 15px;
  margin: 0 -15px;
  border-radius: 8px;
}

.metric.clickable:hover {
  background: rgba(79, 172, 254, 0.1);
  transform: translateX(4px);
}

.chevron-icon {
  width: 18px;
  height: 18px;
  color: #4facfe;
  opacity: 0;
  transition: opacity 0.2s;
}

.metric.clickable:hover .chevron-icon {
  opacity: 1;
}

.metric-label {
  color: #a0aec0;
  font-size: 1em;
}

.metric-value {
  font-size: 1.5em;
  font-weight: bold;
  color: #4facfe;
}

.empty {
  text-align: center;
  color: #718096;
  padding: 20px;
}
</style>

