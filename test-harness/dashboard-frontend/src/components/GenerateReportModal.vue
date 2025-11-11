<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <FileText class="modal-title-icon" />
              <h2>Generate Report</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>

          <div class="modal-body">
            <form @submit.prevent="handleGenerate">
              <!-- Report Name -->
              <div class="form-group">
                <label>Report Name</label>
                <input
                  v-model="form.name"
                  type="text"
                  placeholder="Enter report name"
                  class="form-input"
                />
              </div>

              <!-- Format Selection -->
              <div class="form-group">
                <label>Report Format</label>
                <div class="format-options">
                  <label
                    v-for="format in formatOptions"
                    :key="format.value"
                    class="format-option"
                    :class="{ active: form.format === format.value }"
                  >
                    <input
                      v-model="form.format"
                      type="radio"
                      :value="format.value"
                      class="format-radio"
                    />
                    <span class="format-label">{{ format.label }}</span>
                  </label>
                </div>
              </div>

              <!-- Date Range -->
              <div class="form-row">
                <div class="form-group">
                  <label>From Date</label>
                  <input
                    v-model="form.dateFrom"
                    type="date"
                    class="form-input"
                  />
                </div>
                <div class="form-group">
                  <label>To Date</label>
                  <input
                    v-model="form.dateTo"
                    type="date"
                    class="form-input"
                  />
                </div>
              </div>

              <!-- Applications Filter -->
              <div class="form-group" v-if="applications && applications.length > 0">
                <label>Applications (Optional)</label>
                <div class="checkbox-group">
                  <label
                    v-for="app in applications"
                    :key="app"
                    class="checkbox-option"
                  >
                    <input
                      v-model="form.selectedApplications"
                      type="checkbox"
                      :value="app"
                      class="checkbox-input"
                    />
                    <span>{{ app }}</span>
                  </label>
                </div>
              </div>

              <!-- Teams Filter -->
              <div class="form-group" v-if="teams && teams.length > 0">
                <label>Teams (Optional)</label>
                <div class="checkbox-group">
                  <label
                    v-for="team in teams"
                    :key="team"
                    class="checkbox-option"
                  >
                    <input
                      v-model="form.selectedTeams"
                      type="checkbox"
                      :value="team"
                      class="checkbox-input"
                    />
                    <span>{{ team }}</span>
                  </label>
                </div>
              </div>

              <!-- Validators Filter -->
              <div class="form-group" v-if="validators && validators.length > 0">
                <label>Validators (Optional)</label>
                <div class="checkbox-group">
                  <label
                    v-for="validator in validators"
                    :key="validator.id"
                    class="checkbox-option"
                  >
                    <input
                      v-model="form.selectedValidators"
                      type="checkbox"
                      :value="validator.id"
                      class="checkbox-input"
                    />
                    <span>{{ validator.name || validator.id }}</span>
                  </label>
                </div>
              </div>

              <!-- Options -->
              <div class="form-group">
                <label>Report Options</label>
                <div class="checkbox-group">
                  <label class="checkbox-option">
                    <input
                      v-model="form.includeCharts"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Include Charts & Visualizations</span>
                  </label>
                  <label class="checkbox-option">
                    <input
                      v-model="form.includeDetails"
                      type="checkbox"
                      class="checkbox-input"
                    />
                    <span>Include Detailed Test Results</span>
                  </label>
                </div>
              </div>

              <!-- Schedule (Future Feature) -->
              <div class="form-group">
                <label class="checkbox-option">
                  <input
                    v-model="form.scheduleEnabled"
                    type="checkbox"
                    class="checkbox-input"
                  />
                  <span>Schedule Automated Reports</span>
                </label>
                <div v-if="form.scheduleEnabled" class="schedule-options">
                  <select v-model="form.scheduleFrequency" class="form-input">
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                    <option value="monthly">Monthly</option>
                  </select>
                </div>
              </div>

              <!-- Actions -->
              <div class="modal-actions">
                <button type="button" @click="close" class="btn-secondary">
                  Cancel
                </button>
                <button type="submit" class="btn-primary" :disabled="isGenerating">
                  <Loader2 v-if="isGenerating" class="btn-icon spinning" />
                  <FileText v-else class="btn-icon" />
                  {{ isGenerating ? 'Generating...' : 'Generate Report' }}
                </button>
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
import { Teleport } from 'vue';
import { FileText, X, Loader2 } from 'lucide-vue-next';
import axios from 'axios';

const props = defineProps<{
  isOpen: boolean;
  applications?: string[];
  teams?: string[];
  validators?: any[];
}>();

const emit = defineEmits<{
  'update:isOpen': [value: boolean];
  'generated': [report: any];
}>();

const isGenerating = ref(false);

const form = ref({
  name: '',
  format: 'html' as 'json' | 'html' | 'xml',
  dateFrom: '',
  dateTo: '',
  selectedApplications: [] as string[],
  selectedTeams: [] as string[],
  selectedValidators: [] as string[],
  includeCharts: true,
  includeDetails: true,
  scheduleEnabled: false,
  scheduleFrequency: 'weekly' as 'daily' | 'weekly' | 'monthly',
});

const formatOptions = [
  { label: 'HTML', value: 'html' },
  { label: 'JSON', value: 'json' },
  { label: 'XML', value: 'xml' },
];


const close = () => {
  emit('update:isOpen', false);
};

const handleGenerate = async () => {
  isGenerating.value = true;
  try {
    const response = await axios.post('/api/reports/generate', {
      name: form.value.name || undefined,
      format: form.value.format,
      dateFrom: form.value.dateFrom || undefined,
      dateTo: form.value.dateTo || undefined,
      applicationIds: form.value.selectedApplications.length > 0
        ? form.value.selectedApplications
        : undefined,
      teamIds: form.value.selectedTeams.length > 0
        ? form.value.selectedTeams
        : undefined,
      validatorIds: form.value.selectedValidators.length > 0
        ? form.value.selectedValidators
        : undefined,
      includeCharts: form.value.includeCharts,
      includeDetails: form.value.includeDetails,
    });

    emit('generated', response.data);
    close();
    
    // Reset form
    form.value = {
      name: '',
      format: 'html',
      dateFrom: '',
      dateTo: '',
      selectedApplications: [],
      selectedTeams: [],
      selectedValidators: [],
      includeCharts: true,
      includeDetails: true,
      scheduleEnabled: false,
      scheduleFrequency: 'weekly',
    };
  } catch (error) {
    console.error('Failed to generate report:', error);
    alert('Failed to generate report. Please try again.');
  } finally {
    isGenerating.value = false;
  }
};

watch(() => props.isOpen, (newVal) => {
  if (newVal) {
    // Set default date range to last 30 days
    const toDate = new Date();
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - 30);
    form.value.dateTo = toDate.toISOString().split('T')[0];
    form.value.dateFrom = fromDate.toISOString().split('T')[0];
  }
});
</script>

<style scoped>
.modal-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.modal-content {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  width: 100%;
  max-width: 600px;
  max-height: 90vh;
  overflow-y: auto;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.modal-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
}

.modal-title-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.modal-title-icon {
  width: 24px;
  height: 24px;
  color: #4facfe;
}

.modal-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.modal-close {
  padding: 8px;
  background: transparent;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  color: #a0aec0;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
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

.form-group {
  margin-bottom: 20px;
}

.form-group label {
  display: block;
  margin-bottom: 8px;
  font-size: 0.875rem;
  font-weight: 500;
  color: #a0aec0;
}

.form-input {
  width: 100%;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  transition: all 0.2s;
}

.form-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
}

.format-options {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.format-option {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.format-option:hover {
  border-color: rgba(79, 172, 254, 0.4);
}

.format-option.active {
  background: rgba(79, 172, 254, 0.2);
  border-color: #4facfe;
}

.format-radio {
  margin: 0;
}

.format-label {
  color: #ffffff;
  font-size: 0.9rem;
}

.checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.checkbox-option {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  color: #ffffff;
  font-size: 0.9rem;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.schedule-options {
  margin-top: 12px;
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  font-size: 0.9rem;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover:not(:disabled) {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-primary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
}

.btn-icon {
  width: 18px;
  height: 18px;
}

.btn-icon.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from {
    transform: rotate(0deg);
  }
  to {
    transform: rotate(360deg);
  }
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.3s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>

