<template>
  <div class="distributed-systems-config-form">
    <div class="form-section">
      <h3>Regions *</h3>
      <div v-for="(region, index) in localData.regions" :key="index" class="region-item">
        <div class="form-group">
          <label>Region ID *</label>
          <input v-model="region.id" type="text" required />
        </div>
        <div class="form-group">
          <label>Region Name *</label>
          <input v-model="region.name" type="text" required />
        </div>
        <div class="form-group">
          <label>Endpoint *</label>
          <input v-model="region.endpoint" type="text" required placeholder="https://api.example.com" />
        </div>
        <div class="form-group">
          <label>PDP Endpoint (optional)</label>
          <input v-model="region.pdpEndpoint" type="text" placeholder="https://pdp.example.com/v1/evaluate" />
        </div>
        <div class="form-group">
          <label>Timezone (optional)</label>
          <input v-model="region.timezone" type="text" placeholder="America/New_York" />
        </div>
        <div class="form-group">
          <label>Latency (ms, optional)</label>
          <input v-model.number="region.latency" type="number" min="0" />
        </div>
        <button @click="removeRegion(index)" class="btn-danger">Remove</button>
      </div>
      <button @click="addRegion" class="btn-secondary">Add Region</button>
    </div>

    <div class="form-section">
      <h3>Policy Synchronization</h3>
      <div class="form-group">
        <label>
          <input v-model="localData.policySync.enabled" type="checkbox" />
          Enable Policy Synchronization
        </label>
      </div>
      <div v-if="localData.policySync.enabled" class="sync-options">
        <div class="form-group">
          <label>Sync Interval (ms)</label>
          <input v-model.number="localData.policySync.syncInterval" type="number" min="100" />
        </div>
        <div class="form-group">
          <label>Consistency Level</label>
          <select v-model="localData.policySync.consistencyLevel">
            <option value="strong">Strong</option>
            <option value="eventual">Eventual</option>
            <option value="weak">Weak</option>
          </select>
        </div>
      </div>
    </div>

    <div class="form-section">
      <h3>Coordination (optional)</h3>
      <div class="form-group">
        <label>Coordination Type</label>
        <select v-model="localData.coordination.type">
          <option value="">None</option>
          <option value="consul">Consul</option>
          <option value="etcd">etcd</option>
          <option value="zookeeper">ZooKeeper</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div v-if="localData.coordination.type" class="form-group">
        <label>Endpoint</label>
        <input v-model="localData.coordination.endpoint" type="text" placeholder="https://coord.example.com" />
      </div>
    </div>

    <div class="form-section">
      <h3>Test Logic</h3>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.validateConsistency" type="checkbox" />
          Validate Consistency
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.checkSynchronization" type="checkbox" />
          Check Synchronization
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
  regions: [] as any[],
  policySync: {
    enabled: false,
    syncInterval: 1000,
    consistencyLevel: 'eventual' as 'strong' | 'eventual' | 'weak',
  },
  coordination: {
    type: '' as '' | 'consul' | 'etcd' | 'zookeeper' | 'custom',
    endpoint: '',
  },
  testLogic: {
    validateConsistency: true,
    checkSynchronization: true,
  },
  ...(props.config || props.modelValue || {}),
});

// Ensure regions array exists
if (!localData.value.regions || localData.value.regions.length === 0) {
  localData.value.regions = [];
}

// Ensure policySync object exists
if (!localData.value.policySync) {
  localData.value.policySync = {
    enabled: false,
    syncInterval: 1000,
    consistencyLevel: 'eventual',
  };
}

// Ensure coordination object exists
if (!localData.value.coordination) {
  localData.value.coordination = {
    type: '',
    endpoint: '',
  };
}

// Ensure testLogic object exists
if (!localData.value.testLogic) {
  localData.value.testLogic = {
    validateConsistency: true,
    checkSynchronization: true,
  };
}

watch(() => props.modelValue, (newVal) => {
  if (newVal) {
    Object.assign(localData.value, newVal);
    if (!localData.value.regions) {
      localData.value.regions = [];
    }
    if (!localData.value.policySync) {
      localData.value.policySync = {
        enabled: false,
        syncInterval: 1000,
        consistencyLevel: 'eventual',
      };
    }
    if (!localData.value.coordination) {
      localData.value.coordination = {
        type: '',
        endpoint: '',
      };
    }
    if (!localData.value.testLogic) {
      localData.value.testLogic = {
        validateConsistency: true,
        checkSynchronization: true,
      };
    }
  }
}, { deep: true });

watch(localData, (newVal) => {
  emit('update:modelValue', { ...props.modelValue, ...newVal });
}, { deep: true });

const addRegion = () => {
  localData.value.regions.push({
    id: '',
    name: '',
    endpoint: '',
    pdpEndpoint: '',
    timezone: '',
    latency: undefined,
  });
};

const removeRegion = (index: number) => {
  localData.value.regions.splice(index, 1);
};
</script>

<style scoped>
.distributed-systems-config-form {
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
.form-group select,
.form-group textarea {
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
.form-group select:focus,
.form-group textarea:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-group select option {
  background: #1a1f2e;
  color: #ffffff;
}

.region-item {
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
  background: rgba(15, 20, 25, 0.2);
}

.sync-options {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
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

