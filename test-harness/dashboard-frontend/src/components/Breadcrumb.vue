<template>
  <nav class="breadcrumb" aria-label="Breadcrumb">
    <ol class="breadcrumb-list">
      <li
        v-for="(item, index) in items"
        :key="index"
        class="breadcrumb-item"
        :class="{ 'is-active': index === items.length - 1 }"
      >
        <router-link
          v-if="index < items.length - 1 && item.to"
          :to="item.to"
          class="breadcrumb-link"
        >
          <span>{{ item.label }}</span>
        </router-link>
        <span v-else class="breadcrumb-current">
          <span>{{ item.label }}</span>
        </span>
      </li>
    </ol>
  </nav>
</template>

<script setup lang="ts">
export interface BreadcrumbItem {
  label: string;
  to?: string;
}

defineProps<{
  items: BreadcrumbItem[];
}>();
</script>

<style scoped>
.breadcrumb {
  margin-top: 16px;
  margin-bottom: 24px;
}

.breadcrumb-list {
  display: flex;
  align-items: center;
  gap: 8px;
  list-style: none;
  padding: 0;
  margin: 0;
  flex-wrap: wrap;
}

.breadcrumb-item {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 0.875rem;
}

.breadcrumb-link {
  color: var(--color-primary);
  text-decoration: none;
  transition: var(--transition-color);
  padding: var(--spacing-xs) 0;
}

.breadcrumb-link:hover {
  color: var(--color-secondary);
  text-decoration: underline;
}

.breadcrumb-current {
  color: var(--color-text-secondary);
  font-weight: var(--font-weight-medium);
}
</style>

