<template>
  <div class="policy-json-section">
    <div class="json-viewer">
      <div class="viewer-header">
        <h2 class="section-title">
          <FileCode class="title-icon" />
          Policy JSON
        </h2>
        <BaseButton label="Copy" :icon="Copy" size="sm" @click="copyJSON" />
      </div>
      <pre class="json-content">{{ JSON.stringify(policyJSON, null, 2) }}</pre>
    </div>
  </div>
</template>

<script setup lang="ts">
import { FileCode, Copy } from 'lucide-vue-next';
import BaseButton from '../../../components/BaseButton.vue';

interface Props {
  policyJSON: Record<string, unknown>;
}

const props = defineProps<Props>();

const copyJSON = async () => {
  try {
    const jsonString = JSON.stringify(props.policyJSON, null, 2);
    await navigator.clipboard.writeText(jsonString);
    alert('JSON copied to clipboard');
  } catch (err) {
    console.error('Failed to copy JSON:', err);
    alert('Failed to copy JSON to clipboard');
  }
};
</script>

<style scoped>
.policy-json-section {
  margin-bottom: var(--spacing-xl);
}

.json-viewer {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.viewer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: var(--spacing-md);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.json-content {
  margin: 0;
  padding: var(--spacing-md);
  background: var(--color-bg-overlay);
  border-radius: var(--border-radius-md);
  font-family: 'Courier New', monospace;
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
  overflow-x: auto;
  white-space: pre-wrap;
  word-wrap: break-word;
}
</style>
