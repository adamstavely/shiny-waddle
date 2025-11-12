<template>
  <div class="network-policy-config-form">
    <div class="form-section">
      <h3>Firewall Rules</h3>
      <div v-for="(rule, index) in localData.firewallRules" :key="index" class="rule-item">
        <div class="form-group">
          <label>Rule ID *</label>
          <input v-model="rule.id" type="text" required />
        </div>
        <div class="form-group">
          <label>Rule Name *</label>
          <input v-model="rule.name" type="text" required />
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Source</label>
            <input v-model="rule.source" type="text" />
          </div>
          <div class="form-group">
            <label>Destination</label>
            <input v-model="rule.destination" type="text" />
          </div>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Protocol</label>
            <select v-model="rule.protocol">
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="icmp">ICMP</option>
            </select>
          </div>
          <div class="form-group">
            <label>Port</label>
            <input v-model.number="rule.port" type="number" />
          </div>
        </div>
        <div class="form-group">
          <label>Action</label>
          <select v-model="rule.action">
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </div>
        <div class="form-group">
          <label>
            <input v-model="rule.enabled" type="checkbox" />
            Enabled
          </label>
        </div>
        <button @click="removeRule(index)" class="btn-danger">Remove</button>
      </div>
      <button @click="addRule" class="btn-secondary">Add Firewall Rule</button>
    </div>

    <div class="form-section">
      <h3>Network Segments</h3>
      <div v-for="(segment, index) in localData.networkSegments" :key="index" class="segment-item">
        <div class="form-group">
          <label>Segment ID *</label>
          <input v-model="segment.id" type="text" required />
        </div>
        <div class="form-group">
          <label>Segment Name *</label>
          <input v-model="segment.name" type="text" required />
        </div>
        <div class="form-group">
          <label>CIDR</label>
          <input v-model="segment.cidr" type="text" />
        </div>
        <div class="form-group">
          <label>Services (comma-separated)</label>
          <input v-model="segment.services" type="text" />
        </div>
        <div class="form-group">
          <label>Allowed Connections (comma-separated)</label>
          <input v-model="segment.allowedConnections" type="text" />
        </div>
        <div class="form-group">
          <label>Denied Connections (comma-separated)</label>
          <input v-model="segment.deniedConnections" type="text" />
        </div>
        <button @click="removeSegment(index)" class="btn-danger">Remove</button>
      </div>
      <button @click="addSegment" class="btn-secondary">Add Network Segment</button>
    </div>

    <div class="form-section">
      <h3>Test Logic</h3>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.validateConnectivity" type="checkbox" />
          Validate Connectivity
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.checkSegmentation" type="checkbox" />
          Check Segmentation
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
  firewallRules: [] as any[],
  networkSegments: [] as any[],
  testLogic: {
    validateConnectivity: true,
    checkSegmentation: true,
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

const addRule = () => {
  localData.value.firewallRules.push({
    id: '',
    name: '',
    source: '',
    destination: '',
    protocol: 'tcp',
    port: 80,
    action: 'allow',
    enabled: true,
  });
};

const removeRule = (index: number) => {
  localData.value.firewallRules.splice(index, 1);
};

const addSegment = () => {
  localData.value.networkSegments.push({
    id: '',
    name: '',
    cidr: '',
    services: '',
    allowedConnections: '',
    deniedConnections: '',
  });
};

const removeSegment = (index: number) => {
  localData.value.networkSegments.splice(index, 1);
};
</script>

<style scoped>
.network-policy-config-form {
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

.form-group input,
.form-group select {
  width: 100%;
  padding: 0.5rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 0.875rem;
  color: #ffffff;
  transition: all 0.2s;
}

.form-group input:focus,
.form-group select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group select option {
  background: #1a1f2e;
  color: #ffffff;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.rule-item,
.segment-item {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
  background: rgba(15, 20, 25, 0.2);
}

.btn-secondary,
.btn-danger {
  padding: 0.5rem 1rem;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.btn-danger {
  background: rgba(252, 129, 129, 0.1);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.btn-danger:hover {
  background: rgba(252, 129, 129, 0.2);
  border-color: rgba(252, 129, 129, 0.5);
}
</style>

