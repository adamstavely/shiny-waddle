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
  background: var(--gradient-card-alt);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-xl);
  box-shadow: var(--shadow-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.card h2 {
  color: var(--color-text-primary);
  margin-bottom: var(--spacing-xl);
  font-size: var(--font-size-2xl);
  border-bottom: var(--border-width-medium) solid var(--color-primary);
  padding-bottom: var(--spacing-sm);
  font-weight: var(--font-weight-semibold);
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.metric {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: var(--spacing-md) 0;
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  transition: var(--transition-all);
}

.metric:last-child {
  border-bottom: none;
}

.metric.clickable {
  cursor: pointer;
  padding: var(--spacing-md);
  margin: 0 calc(-1 * var(--spacing-md));
  border-radius: var(--border-radius-md);
}

.metric.clickable:hover {
  background: var(--border-color-muted);
  transform: translateX(4px);
}

.chevron-icon {
  width: 18px;
  height: 18px;
  color: var(--color-primary);
  opacity: 0;
  transition: var(--transition-base);
}

.metric.clickable:hover .chevron-icon {
  opacity: 1;
}

.metric-label {
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.metric-value {
  font-size: var(--font-size-2xl);
  font-weight: var(--font-weight-bold);
  color: var(--color-primary);
}

.empty {
  text-align: center;
  color: var(--color-text-muted);
  padding: var(--spacing-xl);
}
</style>

