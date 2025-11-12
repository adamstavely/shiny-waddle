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
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 24px 30px;
  margin-bottom: 30px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.header-content {
  display: flex;
  align-items: center;
  gap: 20px;
}

.icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  stroke-width: 2;
}

.header-text h1 {
  color: #ffffff;
  font-size: 2em;
  margin-bottom: 8px;
  font-weight: 600;
  letter-spacing: -0.5px;
}

.header-text p {
  color: #a0aec0;
  font-size: 1.1em;
  margin: 0;
}
</style>

