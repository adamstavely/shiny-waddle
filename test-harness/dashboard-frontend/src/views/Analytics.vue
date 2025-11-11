<template>
  <div class="analytics-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <h1 class="page-title">Analytics</h1>
      <p class="page-description">Compliance analytics and insights</p>
    </div>
    
    <div class="page-content">
      <div class="placeholder-card">
        <BarChart3 class="placeholder-icon" />
        <h2>Analytics Dashboard</h2>
        <p>Advanced analytics and reporting interface coming soon.</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { BarChart3 } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Analytics', icon: BarChart3 }
];
</script>

<style scoped>
.analytics-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.page-description {
  font-size: 1.1rem;
  color: #a0aec0;
}

.page-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.placeholder-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 64px;
  text-align: center;
}

.placeholder-icon {
  width: 64px;
  height: 64px;
  color: #4facfe;
  margin: 0 auto 24px;
}

.placeholder-card h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.placeholder-card p {
  font-size: 1rem;
  color: #a0aec0;
}
</style>

