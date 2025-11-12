<template>
  <div class="identity-lifecycle-config-form">
    <div class="form-section">
      <h3>Onboarding Workflow</h3>
      <div class="form-group">
        <label>Workflow Steps (comma-separated)</label>
        <input v-model="localData.onboardingWorkflow.steps" type="text" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.onboardingWorkflow.requireMFA" type="checkbox" />
          Require MFA on Onboarding
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.onboardingWorkflow.requireApproval" type="checkbox" />
          Require Approval
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>PAM Configuration</h3>
      <div class="form-group">
        <label>Maximum JIT Duration (minutes)</label>
        <input v-model.number="localData.pamConfig.maxJITDuration" type="number" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.pamConfig.requireApproval" type="checkbox" />
          Require Approval for JIT Access
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.pamConfig.emergencyAccessEnabled" type="checkbox" />
          Emergency Access Enabled
        </label>
      </div>
    </div>

    <div class="form-section">
      <h3>Credential Rotation Rules</h3>
      <div class="form-group">
        <label>Rotation Interval (days)</label>
        <input v-model.number="localData.credentialRotation.intervalDays" type="number" />
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.credentialRotation.enforceRotation" type="checkbox" />
          Enforce Rotation
        </label>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';

const props = defineProps<{
  config?: any;
  modelValue?: any;
}>();

const emit = defineEmits<{
  'update:modelValue': [value: any];
}>();

const localData = ref({
  onboardingWorkflow: {
    steps: '',
    requireMFA: true,
    requireApproval: false,
  },
  pamConfig: {
    maxJITDuration: 60,
    requireApproval: true,
    emergencyAccessEnabled: true,
  },
  credentialRotation: {
    intervalDays: 90,
    enforceRotation: true,
  },
  ...(props.config || props.modelValue || {}),
});

watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    Object.assign(localData.value, newVal);
  }
}, { deep: true });

watch(localData, (newVal) => {
  emit('update:modelValue', { ...props.modelValue, ...newVal });
}, { deep: true });
</script>

<style scoped>
.identity-lifecycle-config-form {
  display: flex;
  flex-direction: column;
  gap: 2rem;
}

.form-section {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1.5rem;
  background: rgba(15, 20, 25, 0.4);
}

.form-section h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
  color: #a0aec0;
  font-size: 0.9rem;
}

.form-group input {
  width: 100%;
  padding: 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
  transition: all 0.2s;
}

.form-group input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}
</style>

