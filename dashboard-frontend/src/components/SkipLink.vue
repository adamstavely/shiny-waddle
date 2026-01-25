<template>
  <a
    href="#main-content"
    class="skip-link"
    @click.prevent="skipToMain"
  >
    Skip to main content
  </a>
</template>

<script setup lang="ts">
import { skipToMainContent } from '../utils/accessibility';

const skipToMain = () => {
  skipToMainContent();
};
</script>

<style scoped>
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  background: #4facfe;
  color: #0f1419;
  padding: 8px 16px;
  text-decoration: none;
  font-weight: 600;
  z-index: 10000;
  border-radius: 0 0 4px 0;
  transition: top 0.2s;
}

.skip-link:focus {
  top: 0;
  outline: 3px solid #00f2fe;
  outline-offset: 2px;
}
</style>

