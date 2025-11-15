<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show" class="modal-overlay" @click="$emit('close')">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>{{ config ? 'Edit Configuration' : 'New Configuration' }}</h2>
            <button @click="$emit('close')" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleSubmit">
              <div class="form-group">
                <label>Name</label>
                <input v-model="formData.name" type="text" required class="form-input" />
              </div>

              <div class="form-group">
                <label>Pipeline Type</label>
                <select v-model="formData.pipelineType" required class="form-input">
                  <option value="etl">ETL</option>
                  <option value="streaming">Streaming</option>
                  <option value="batch">Batch</option>
                  <option value="real-time">Real-time</option>
                </select>
              </div>

              <div class="form-section">
                <h3>Connection</h3>
                <div class="form-group">
                  <label>Type</label>
                  <select v-model="formData.connection.type" class="form-input">
                    <option value="">None</option>
                    <option value="kafka">Kafka</option>
                    <option value="spark">Spark</option>
                    <option value="airflow">Airflow</option>
                    <option value="dbt">dbt</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div v-if="formData.connection.type" class="form-group">
                  <label>Endpoint</label>
                  <input v-model="formData.connection.endpoint" type="text" class="form-input" placeholder="http://example.com:8080" />
                </div>
                <div v-if="formData.connection.type" class="form-group">
                  <label>Credentials (JSON)</label>
                  <textarea
                    v-model="connectionCredentialsJson"
                    class="form-input"
                    rows="3"
                    placeholder='{"username": "...", "password": "..."}'
                  ></textarea>
                </div>
              </div>

              <div class="form-section">
                <h3>Data Source</h3>
                <div class="form-group">
                  <label>Type</label>
                  <select v-model="formData.dataSource.type" class="form-input">
                    <option value="">None</option>
                    <option value="database">Database</option>
                    <option value="api">API</option>
                    <option value="file">File</option>
                    <option value="stream">Stream</option>
                  </select>
                </div>
                <div v-if="formData.dataSource.type" class="form-group">
                  <label>Connection String</label>
                  <input v-model="formData.dataSource.connectionString" type="text" class="form-input" placeholder="postgresql://..." />
                </div>
              </div>

              <div class="form-section">
                <h3>Data Destination</h3>
                <div class="form-group">
                  <label>Type</label>
                  <select v-model="formData.dataDestination.type" class="form-input">
                    <option value="">None</option>
                    <option value="database">Database</option>
                    <option value="data-warehouse">Data Warehouse</option>
                    <option value="data-lake">Data Lake</option>
                    <option value="api">API</option>
                  </select>
                </div>
                <div v-if="formData.dataDestination.type" class="form-group">
                  <label>Connection String</label>
                  <input v-model="formData.dataDestination.connectionString" type="text" class="form-input" placeholder="snowflake://..." />
                </div>
              </div>

              <div class="form-actions">
                <button type="button" @click="$emit('close')" class="cancel-btn">Cancel</button>
                <button type="submit" class="save-btn">Save</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue';
import { X } from 'lucide-vue-next';
import type { DataPipelineConfigurationEntity } from '../types/data-pipeline';

interface Props {
  show: boolean;
  config: DataPipelineConfigurationEntity | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  save: [config: DataPipelineConfigurationEntity];
}>();

const formData = ref({
  name: '',
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

watch(() => props.config, (newConfig) => {
  if (newConfig) {
    formData.value = {
      name: newConfig.name,
      pipelineType: newConfig.pipelineType,
      connection: newConfig.connection || { type: '', endpoint: '', credentials: {} },
      dataSource: newConfig.dataSource || { type: '', connectionString: '' },
      dataDestination: newConfig.dataDestination || { type: '', connectionString: '' },
    };
    connectionCredentialsJson.value = JSON.stringify(newConfig.connection?.credentials || {}, null, 2);
  } else {
    formData.value = {
      name: '',
      pipelineType: 'etl',
      connection: { type: '', endpoint: '', credentials: {} },
      dataSource: { type: '', connectionString: '' },
      dataDestination: { type: '', connectionString: '' },
    };
    connectionCredentialsJson.value = '{}';
  }
}, { immediate: true });

const handleSubmit = async () => {
  try {
    const credentials = JSON.parse(connectionCredentialsJson.value || '{}');
    
    const configData: any = {
      ...formData.value,
      connection: formData.value.connection.type
        ? { ...formData.value.connection, credentials }
        : undefined,
      dataSource: formData.value.dataSource.type
        ? formData.value.dataSource
        : undefined,
      dataDestination: formData.value.dataDestination.type
        ? formData.value.dataDestination
        : undefined,
    };

    if (props.config) {
      configData.id = props.config.id;
    }

    emit('save', configData as DataPipelineConfigurationEntity);
    emit('close');
  } catch (error) {
    console.error('Error parsing credentials:', error);
    alert('Invalid JSON in credentials field');
  }
};
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.75);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 8px;
  transition: all 0.2s;
}

.modal-close:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.modal-body {
  padding: 24px;
}

.form-section {
  margin-bottom: 24px;
  padding-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
}

.form-section:last-child {
  border-bottom: none;
}

.form-section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 16px;
}

.form-group {
  margin-bottom: 16px;
}

.form-group label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
  margin-bottom: 8px;
}

.form-input {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  font-family: inherit;
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-input textarea {
  resize: vertical;
  font-family: 'Courier New', monospace;
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.cancel-btn,
.save-btn {
  padding: 10px 24px;
  border-radius: 8px;
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.cancel-btn {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.cancel-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.save-btn {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  border: none;
  color: #ffffff;
}

.save-btn:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

