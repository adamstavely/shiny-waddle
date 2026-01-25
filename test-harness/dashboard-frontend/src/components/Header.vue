<template>
  <div class="header">
    <div class="header-content">
      <Shield class="icon" />
      <div class="header-text">
        <h1>Heimdall</h1>
        <p>Compliance Dashboard - Real-time access control monitoring</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Shield } from 'lucide-vue-next';
</script>

<style scoped>
.header {
  background: var(--gradient-card);
  border-radius: var(--border-radius-lg);
  padding: var(--spacing-lg) 30px;
  margin-bottom: 30px;
  box-shadow: var(--shadow-md);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.header-content {
  display: flex;
  align-items: center;
  gap: var(--spacing-xl);
}

.icon {
  width: 48px;
  height: 48px;
  color: var(--color-primary);
  stroke-width: 2;
}

.header-text h1 {
  color: var(--color-text-primary);
  font-size: var(--font-size-3xl);
  margin-bottom: var(--spacing-sm);
  font-weight: var(--font-weight-semibold);
  letter-spacing: -0.5px;
}

.header-text p {
  color: var(--color-text-secondary);
  font-size: 1.1em;
  margin: 0;
}
</style>

