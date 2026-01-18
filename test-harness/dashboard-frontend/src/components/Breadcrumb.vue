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
  color: #a0aec0;
  font-weight: 500;
}
</style>

