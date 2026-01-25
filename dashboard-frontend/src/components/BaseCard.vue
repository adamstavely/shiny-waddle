<template>
  <div 
    class="base-card" 
    :class="[
      `card-${variant}`,
      { 'card-clickable': clickable, 'card-disabled': disabled }
    ]"
    @click="handleClick"
  >
    <div v-if="$slots.header || title || icon" class="card-header">
      <div v-if="icon || title" class="card-title-group">
        <component v-if="icon" :is="icon" class="card-icon" />
        <h3 v-if="title" class="card-title">{{ title }}</h3>
      </div>
      <slot name="header" />
    </div>
    
    <div class="card-body">
      <slot />
    </div>
    
    <div v-if="$slots.footer" class="card-footer">
      <slot name="footer" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { type LucideIcon } from 'lucide-vue-next';

interface Props {
  title?: string;
  icon?: LucideIcon;
  variant?: 'default' | 'alt' | 'elevated';
  clickable?: boolean;
  disabled?: boolean;
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'default',
  clickable: false,
  disabled: false,
});

const emit = defineEmits<{
  click: [event: MouseEvent];
}>();

const handleClick = (event: MouseEvent) => {
  if (props.clickable && !props.disabled) {
    emit('click', event);
  }
};
</script>

<style scoped>
.base-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  transition: var(--transition-all);
  display: flex;
  flex-direction: column;
}

.base-card.card-alt {
  background: var(--gradient-card-alt);
}

.base-card.card-elevated {
  box-shadow: var(--shadow-lg);
}

.base-card.card-clickable {
  cursor: pointer;
}

.base-card.card-clickable:hover:not(.card-disabled) {
  border-color: var(--border-color-primary-hover);
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.base-card.card-disabled {
  opacity: var(--opacity-disabled);
  cursor: not-allowed;
}

.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.card-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  flex: 1;
}

.card-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.card-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.card-body {
  flex: 1;
  color: var(--color-text-secondary);
}

.card-footer {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
  display: flex;
  gap: var(--spacing-sm);
  justify-content: flex-end;
}
</style>
