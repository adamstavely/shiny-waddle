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
          <component v-if="item.icon" :is="item.icon" class="breadcrumb-icon" />
          <span>{{ item.label }}</span>
        </router-link>
        <span v-else class="breadcrumb-current">
          <component v-if="item.icon" :is="item.icon" class="breadcrumb-icon" />
          <span>{{ item.label }}</span>
        </span>
        <ChevronRight
          v-if="index < items.length - 1"
          class="breadcrumb-separator"
        />
      </li>
    </ol>
  </nav>
</template>

<script setup lang="ts">
import { ChevronRight } from 'lucide-vue-next';

export interface BreadcrumbItem {
  label: string;
  to?: string;
  icon?: any;
}

defineProps<{
  items: BreadcrumbItem[];
}>();
</script>

<style scoped>
.breadcrumb {
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
  display: flex;
  align-items: center;
  gap: 6px;
  color: #4facfe;
  text-decoration: none;
  transition: color 0.2s;
  padding: 4px 0;
}

.breadcrumb-link:hover {
  color: #00f2fe;
  text-decoration: underline;
}

.breadcrumb-current {
  display: flex;
  align-items: center;
  gap: 6px;
  color: #a0aec0;
  font-weight: 500;
}

.breadcrumb-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.breadcrumb-separator {
  width: 14px;
  height: 14px;
  color: #718096;
  flex-shrink: 0;
  margin-left: 4px;
}
</style>

