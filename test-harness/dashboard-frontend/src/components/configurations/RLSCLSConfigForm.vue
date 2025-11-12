<template>
  <div class="rls-cls-config-form">
    <div class="form-section">
      <h3>Database Configuration</h3>
      <div class="form-group">
        <label>Database Type *</label>
        <select v-model="localData.database.type" required>
          <option value="postgresql">PostgreSQL</option>
          <option value="mysql">MySQL</option>
          <option value="mssql">SQL Server</option>
          <option value="oracle">Oracle</option>
          <option value="sqlite">SQLite</option>
        </select>
      </div>
      <div class="form-group">
        <label>Host</label>
        <input v-model="localData.database.host" type="text" />
      </div>
      <div class="form-group">
        <label>Port</label>
        <input v-model.number="localData.database.port" type="number" />
      </div>
      <div class="form-group">
        <label>Database Name</label>
        <input v-model="localData.database.database" type="text" />
      </div>
      <div class="form-group">
        <label>Username</label>
        <input v-model="localData.database.username" type="text" />
      </div>
      <div class="form-group">
        <label>Password</label>
        <input v-model="localData.database.password" type="password" />
      </div>
      <div class="form-group">
        <label>Connection String</label>
        <input v-model="localData.database.connectionString" type="text" />
      </div>
    </div>

    <div class="form-section">
      <h3>Test Queries</h3>
      <div v-for="(query, index) in localData.testQueries" :key="index" class="query-item">
        <div class="form-group">
          <label>Query Name *</label>
          <input v-model="query.name" type="text" required />
        </div>
        <div class="form-group">
          <label>SQL</label>
          <textarea v-model="query.sql" rows="3"></textarea>
        </div>
        <div class="form-group">
          <label>API Endpoint</label>
          <input v-model="query.apiEndpoint" type="text" />
        </div>
        <div class="form-group">
          <label>Method</label>
          <select v-model="query.method">
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="DELETE">DELETE</option>
          </select>
        </div>
        <button @click="removeQuery(index)" class="btn-danger">Remove</button>
      </div>
      <button @click="addQuery" class="btn-secondary">Add Query</button>
    </div>

    <div class="form-section">
      <h3>Validation Rules</h3>
      <div class="form-group">
        <label>Minimum RLS Coverage (%)</label>
        <input v-model.number="localData.validationRules.minRLSCoverage" type="number" min="0" max="100" />
      </div>
      <div class="form-group">
        <label>Minimum CLS Coverage (%)</label>
        <input v-model.number="localData.validationRules.minCLSCoverage" type="number" min="0" max="100" />
      </div>
      <div class="form-group">
        <label>Required Policies (comma-separated)</label>
        <input v-model="localData.validationRules.requiredPolicies" type="text" />
      </div>
    </div>

    <div class="form-section">
      <h3>Test Logic</h3>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.skipDisabledPolicies" type="checkbox" />
          Skip Disabled Policies
        </label>
      </div>
      <div class="form-group">
        <label>
          <input v-model="localData.testLogic.validateCrossTenant" type="checkbox" />
          Validate Cross-Tenant Isolation
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
  database: {
    type: 'postgresql',
    host: '',
    port: 5432,
    database: '',
    username: '',
    password: '',
    connectionString: '',
  },
  testQueries: [] as any[],
  validationRules: {
    minRLSCoverage: 80,
    minCLSCoverage: 80,
    requiredPolicies: '',
  },
  testLogic: {
    skipDisabledPolicies: true,
    validateCrossTenant: true,
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

const addQuery = () => {
  localData.value.testQueries.push({
    name: '',
    sql: '',
    apiEndpoint: '',
    method: 'GET',
  });
};

const removeQuery = (index: number) => {
  localData.value.testQueries.splice(index, 1);
};
</script>

<style scoped>
.rls-cls-config-form {
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

.query-item {
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

