<template>
  <div class="data-pipeline-config-form">
    <div class="form-section">
      <h3>Pipeline Configuration</h3>
      <div class="form-group">
        <label>Pipeline Type *</label>
        <select v-model="localData.pipelineType" required>
          <option value="etl">ETL</option>
          <option value="streaming">Streaming</option>
          <option value="batch">Batch</option>
          <option value="real-time">Real-time</option>
        </select>
      </div>
    </div>

    <div class="form-section">
      <h3>Connection</h3>
      <div class="form-group">
        <label>Type</label>
        <select v-model="localData.connection.type">
          <option value="">None</option>
          <option value="kafka">Kafka</option>
          <option value="spark">Spark</option>
          <option value="airflow">Airflow</option>
          <option value="dbt">dbt</option>
          <option value="custom">Custom</option>
        </select>
      </div>
      <div v-if="localData.connection.type" class="form-group">
        <label>Endpoint</label>
        <input v-model="localData.connection.endpoint" type="text" placeholder="http://example.com:8080" />
      </div>
      <div v-if="localData.connection.type" class="form-group">
        <label>Credentials (JSON)</label>
        <textarea
          v-model="connectionCredentialsJson"
          rows="3"
          placeholder='{"username": "...", "password": "..."}'
        ></textarea>
      </div>
    </div>

    <div class="form-section">
      <h3>Data Source</h3>
      <div class="form-group">
        <label>Type</label>
        <select v-model="localData.dataSource.type">
          <option value="">None</option>
          <option value="database">Database</option>
          <option value="api">API</option>
          <option value="file">File</option>
          <option value="stream">Stream</option>
        </select>
      </div>
      <div v-if="localData.dataSource.type" class="form-group">
        <label>Connection String</label>
        <input v-model="localData.dataSource.connectionString" type="text" placeholder="postgresql://..." />
      </div>
    </div>

    <div class="form-section">
      <h3>Data Destination</h3>
      <div class="form-group">
        <label>Type</label>
        <select v-model="localData.dataDestination.type">
          <option value="">None</option>
          <option value="database">Database</option>
          <option value="data-warehouse">Data Warehouse</option>
          <option value="data-lake">Data Lake</option>
          <option value="api">API</option>
        </select>
      </div>
      <div v-if="localData.dataDestination.type" class="form-group">
        <label>Connection String</label>
        <input v-model="localData.dataDestination.connectionString" type="text" placeholder="snowflake://..." />
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
  pipelineType: 'etl' as 'etl' | 'streaming' | 'batch' | 'real-time',
  connection: {
    type: '' as 'kafka' | 'spark' | 'airflow' | 'dbt' | 'custom' | '',
    endpoint: '',
    credentials: {} as Record<string, string>,
  },
  dataSource: {
    type: '' as 'database' | 'api' | 'file' | 'stream' | '',
    connectionString: '',
  },
  dataDestination: {
    type: '' as 'database' | 'data-warehouse' | 'data-lake' | 'api' | '',
    connectionString: '',
  },
});

const connectionCredentialsJson = ref('{}');

watch(() => props.config || props.modelValue, (newConfig) => {
  if (newConfig) {
    localData.value = {
      pipelineType: newConfig.pipelineType || 'etl',
      connection: newConfig.connection || { type: '', endpoint: '', credentials: {} },
      dataSource: newConfig.dataSource || { type: '', connectionString: '' },
      dataDestination: newConfig.dataDestination || { type: '', connectionString: '' },
    };
    connectionCredentialsJson.value = JSON.stringify(newConfig.connection?.credentials || {}, null, 2);
  }
}, { immediate: true });

watch([localData, connectionCredentialsJson], () => {
  try {
    const credentials = JSON.parse(connectionCredentialsJson.value || '{}');
    const dataToEmit = {
      ...localData.value,
      connection: localData.value.connection.type
        ? { ...localData.value.connection, credentials }
        : undefined,
      dataSource: localData.value.dataSource.type
        ? localData.value.dataSource
        : undefined,
      dataDestination: localData.value.dataDestination.type
        ? localData.value.dataDestination
        : undefined,
    };
    emit('update:modelValue', dataToEmit);
  } catch (error) {
    // Invalid JSON, emit without credentials
    emit('update:modelValue', localData.value);
  }
}, { deep: true });
</script>

<style scoped>
.data-pipeline-config-form {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.form-section {
  padding: 1rem;
  background: rgba(255, 255, 255, 0.02);
  border-radius: 8px;
  border: 1px solid rgba(79, 172, 254, 0.1);
}

.form-section h3 {
  margin: 0 0 1rem 0;
  color: #ffffff;
  font-size: 1.1rem;
  font-weight: 600;
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
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  font-size: 1rem;
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

.form-group textarea {
  resize: vertical;
  font-family: 'Courier New', monospace;
}
</style>

