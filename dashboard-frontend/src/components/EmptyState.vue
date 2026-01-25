<template>
  <div class="empty-state" :class="{ 'empty-state-compact': compact }">
    <component v-if="icon" :is="icon" class="empty-state-icon" />
    <h3 v-if="title" class="empty-state-title">{{ title }}</h3>
    <p v-if="description" class="empty-state-description">{{ description }}</p>
    <div v-if="$slots.actions || showDefaultAction" class="empty-state-actions">
      <slot name="actions">
        <BaseButton
          v-if="showDefaultAction && actionLabel"
          :label="actionLabel"
          :icon="actionIcon"
          @click="handleAction"
        />
      </slot>
    </div>
  </div>
</template>

<script setup lang="ts">
import { type LucideIcon } from 'lucide-vue-next';
import BaseButton from './BaseButton.vue';

interface Props {
  title?: string;
  description?: string;
  icon?: LucideIcon;
  actionLabel?: string;
  actionIcon?: LucideIcon;
  showDefaultAction?: boolean;
  compact?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  showDefaultAction: false,
  compact: false,
});

const emit = defineEmits<{
  action: [];
}>();

const handleAction = () => {
  emit('action');
};
</script>

<style scoped>
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: var(--spacing-2xl);
  color: var(--color-text-secondary);
}

.empty-state-compact {
  padding: var(--spacing-lg);
}

.empty-state-icon {
  width: 64px;
  height: 64px;
  color: var(--color-text-muted);
  margin-bottom: var(--spacing-lg);
  opacity: 0.5;
}

.empty-state-compact .empty-state-icon {
  width: 48px;
  height: 48px;
  margin-bottom: var(--spacing-md);
}

.empty-state-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-sm) 0;
}

.empty-state-compact .empty-state-title {
  font-size: var(--font-size-lg);
}

.empty-state-description {
  font-size: var(--font-size-base);
  color: var(--color-text-secondary);
  margin: 0 0 var(--spacing-lg) 0;
  max-width: 400px;
}

.empty-state-compact .empty-state-description {
  font-size: var(--font-size-sm);
  margin-bottom: var(--spacing-md);
}

.empty-state-actions {
  display: flex;
  gap: var(--spacing-sm);
  flex-wrap: wrap;
  justify-content: center;
}
</style>
