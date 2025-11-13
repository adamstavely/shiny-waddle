<template>
  <div class="notification-settings-page">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <div class="header-content">
        <div>
          <h1 class="page-title">Notification Settings</h1>
          <p class="page-description">Configure your notification preferences</p>
        </div>
      </div>
    </div>

    <div v-if="loading" class="loading">Loading preferences...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="preferences" class="settings-content">
      <div class="settings-section">
        <div class="setting-item">
          <div class="setting-info">
            <h3>Enable Notifications</h3>
            <p>Receive notifications about security findings and compliance changes</p>
          </div>
          <label class="toggle-switch">
            <input
              type="checkbox"
              v-model="preferences.enabled"
              @change="savePreferences"
            />
            <span class="slider"></span>
          </label>
        </div>

        <div class="setting-item">
          <div class="setting-info">
            <h3>Score Drop Threshold</h3>
            <p>Notify me when compliance score drops by this many points or more</p>
          </div>
          <div class="threshold-control">
            <input
              type="range"
              v-model.number="preferences.scoreDropThreshold"
              min="1"
              max="20"
              @change="savePreferences"
              class="threshold-slider"
            />
            <span class="threshold-value">{{ preferences.scoreDropThreshold }} points</span>
          </div>
        </div>

        <div class="setting-item">
          <div class="setting-info">
            <h3>Notify on Critical Findings</h3>
            <p>Receive notifications when new critical security findings are detected</p>
          </div>
          <label class="toggle-switch">
            <input
              type="checkbox"
              v-model="preferences.notifyOnCriticalFinding"
              @change="savePreferences"
            />
            <span class="slider"></span>
          </label>
        </div>

        <div class="setting-item">
          <div class="setting-info">
            <h3>Notify on Approval Requests</h3>
            <p>Receive notifications when approval requests are created for your findings</p>
          </div>
          <label class="toggle-switch">
            <input
              type="checkbox"
              v-model="preferences.notifyOnApprovalRequest"
              @change="savePreferences"
            />
            <span class="slider"></span>
          </label>
        </div>

        <div class="setting-item">
          <div class="setting-info">
            <h3>Notify on Approval Status Changes</h3>
            <p>Receive notifications when your approval requests are approved or rejected</p>
          </div>
          <label class="toggle-switch">
            <input
              type="checkbox"
              v-model="preferences.notifyOnApprovalStatusChanged"
              @change="savePreferences"
            />
            <span class="slider"></span>
          </label>
        </div>
      </div>

      <div v-if="saveStatus" class="save-status" :class="saveStatus.type">
        {{ saveStatus.message }}
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';
import Breadcrumb from '../components/Breadcrumb.vue';

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Settings', to: '/settings' },
  { label: 'Notification Settings', to: '/settings/notifications' },
];

const loading = ref(true);
const error = ref<string | null>(null);
const preferences = ref<any>(null);
const saveStatus = ref<{ type: 'success' | 'error'; message: string } | null>(null);

const loadPreferences = async () => {
  loading.value = true;
  error.value = null;
  try {
    const response = await axios.get('/api/notifications/preferences');
    preferences.value = response.data;
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load preferences';
    console.error('Failed to load preferences:', err);
  } finally {
    loading.value = false;
  }
};

const savePreferences = async () => {
  if (!preferences.value) return;

  try {
    await axios.patch('/api/notifications/preferences', preferences.value);
    saveStatus.value = { type: 'success', message: 'Preferences saved successfully' };
    setTimeout(() => {
      saveStatus.value = null;
    }, 3000);
  } catch (err: any) {
    saveStatus.value = {
      type: 'error',
      message: err.response?.data?.message || 'Failed to save preferences',
    };
    setTimeout(() => {
      saveStatus.value = null;
    }, 5000);
  }
};

onMounted(() => {
  loadPreferences();
});
</script>

<style scoped>
.notification-settings-page {
  padding: 24px;
  max-width: 1000px;
  margin: 0 auto;
}

.page-header {
  margin-bottom: 32px;
}

.page-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.page-description {
  font-size: 1rem;
  color: #a0aec0;
  margin: 0;
}

.loading,
.error {
  padding: 24px;
  text-align: center;
  color: #ffffff;
}

.error {
  color: #fc8181;
}

.settings-content {
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 32px;
}

.settings-section {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.setting-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 20px;
  background: rgba(0, 0, 0, 0.3);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.setting-info {
  flex: 1;
}

.setting-info h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 8px 0;
}

.setting-info p {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0;
  line-height: 1.5;
}

.toggle-switch {
  position: relative;
  display: inline-block;
  width: 52px;
  height: 28px;
  flex-shrink: 0;
}

.toggle-switch input {
  opacity: 0;
  width: 0;
  height: 0;
}

.slider {
  position: absolute;
  cursor: pointer;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-color: rgba(160, 174, 192, 0.3);
  transition: 0.3s;
  border-radius: 28px;
}

.slider:before {
  position: absolute;
  content: '';
  height: 20px;
  width: 20px;
  left: 4px;
  bottom: 4px;
  background-color: #ffffff;
  transition: 0.3s;
  border-radius: 50%;
}

input:checked + .slider {
  background-color: #4facfe;
}

input:checked + .slider:before {
  transform: translateX(24px);
}

.threshold-control {
  display: flex;
  align-items: center;
  gap: 16px;
  min-width: 200px;
}

.threshold-slider {
  flex: 1;
  height: 6px;
  border-radius: 3px;
  background: rgba(160, 174, 192, 0.3);
  outline: none;
  -webkit-appearance: none;
}

.threshold-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #4facfe;
  cursor: pointer;
}

.threshold-slider::-moz-range-thumb {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: #4facfe;
  cursor: pointer;
  border: none;
}

.threshold-value {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
  min-width: 80px;
  text-align: right;
}

.save-status {
  margin-top: 24px;
  padding: 12px 20px;
  border-radius: 8px;
  font-size: 0.875rem;
  font-weight: 500;
}

.save-status.success {
  background: rgba(34, 197, 94, 0.1);
  color: #22c55e;
  border: 1px solid rgba(34, 197, 94, 0.3);
}

.save-status.error {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}
</style>

