<template>
  <div class="dashboard-customizer">
    <div class="customizer-header">
      <h2>Customize Dashboard</h2>
      <button @click="close" class="close-btn" aria-label="Close customizer">
        <X class="close-icon" />
      </button>
    </div>
    
    <div class="customizer-content">
      <div class="section">
        <h3>Layout</h3>
        <div class="layout-options">
          <label>
            <input
              type="radio"
              v-model="layout"
              value="grid"
              @change="updateLayout"
            />
            Grid Layout
          </label>
          <label>
            <input
              type="radio"
              v-model="layout"
              value="list"
              @change="updateLayout"
            />
            List Layout
          </label>
          <label>
            <input
              type="radio"
              v-model="layout"
              value="compact"
              @change="updateLayout"
            />
            Compact Layout
          </label>
        </div>
      </div>
      
      <div class="section">
        <h3>Widgets</h3>
        <div class="widgets-list">
          <div
            v-for="widget in availableWidgets"
            :key="widget.id"
            class="widget-item"
          >
            <label class="widget-checkbox">
              <input
                type="checkbox"
                :checked="isWidgetEnabled(widget.id)"
                @change="toggleWidget(widget.id, $event)"
              />
              <span class="widget-label">{{ widget.name }}</span>
            </label>
            <div class="widget-description">{{ widget.description }}</div>
          </div>
        </div>
      </div>
      
      <div class="section">
        <h3>Time Range</h3>
        <select v-model="timeRange" @change="updateTimeRange" class="time-range-select">
          <option value="7">Last 7 days</option>
          <option value="30">Last 30 days</option>
          <option value="90">Last 90 days</option>
          <option value="365">Last year</option>
        </select>
      </div>
      
      <div class="section">
        <h3>Refresh Interval</h3>
        <select v-model="refreshInterval" @change="updateRefreshInterval" class="refresh-interval-select">
          <option value="0">Manual refresh only</option>
          <option value="30">30 seconds</option>
          <option value="60">1 minute</option>
          <option value="300">5 minutes</option>
          <option value="600">10 minutes</option>
        </select>
      </div>
    </div>
    
    <div class="customizer-footer">
      <button @click="reset" class="btn-secondary">Reset to Default</button>
      <button @click="save" class="btn-primary">Save Changes</button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { X } from 'lucide-vue-next';

interface Widget {
  id: string;
  name: string;
  description: string;
  defaultEnabled: boolean;
}

interface Props {
  currentLayout?: string;
  enabledWidgets?: string[];
  currentTimeRange?: number;
  currentRefreshInterval?: number;
}

const props = withDefaults(defineProps<Props>(), {
  currentLayout: 'grid',
  enabledWidgets: () => [],
  currentTimeRange: 30,
  currentRefreshInterval: 30,
});

const emit = defineEmits<{
  close: [];
  save: [config: {
    layout: string;
    enabledWidgets: string[];
    timeRange: number;
    refreshInterval: number;
  }];
  update: [config: {
    layout?: string;
    enabledWidgets?: string[];
    timeRange?: number;
    refreshInterval?: number;
  }];
}>();

const layout = ref(props.currentLayout);
const enabledWidgets = ref<string[]>([...props.enabledWidgets]);
const timeRange = ref(props.currentTimeRange);
const refreshInterval = ref(props.currentRefreshInterval);

const availableWidgets: Widget[] = [
  { id: 'overall-score', name: 'Overall Score', description: 'Display overall compliance score', defaultEnabled: true },
  { id: 'score-by-application', name: 'Score by Application', description: 'Show compliance scores by application', defaultEnabled: true },
  { id: 'score-by-team', name: 'Score by Team', description: 'Show compliance scores by team', defaultEnabled: true },
  { id: 'category-scores', name: 'Category Scores', description: 'Show scores by compliance category', defaultEnabled: true },
  { id: 'test-results', name: 'Test Results', description: 'Display recent test results', defaultEnabled: true },
  { id: 'risk-heatmap', name: 'Risk Heatmap', description: 'Visualize risk across applications and categories', defaultEnabled: false },
  { id: 'trends', name: 'Trends', description: 'Show compliance trends over time', defaultEnabled: true },
  { id: 'validator-metrics', name: 'Validator Metrics', description: 'Display validator performance metrics', defaultEnabled: false },
  { id: 'executive-summary', name: 'Executive Summary', description: 'High-level executive metrics', defaultEnabled: true },
];

const isWidgetEnabled = (widgetId: string): boolean => {
  return enabledWidgets.value.includes(widgetId);
};

const toggleWidget = (widgetId: string, event: Event) => {
  const checked = (event.target as HTMLInputElement).checked;
  if (checked) {
    if (!enabledWidgets.value.includes(widgetId)) {
      enabledWidgets.value.push(widgetId);
    }
  } else {
    enabledWidgets.value = enabledWidgets.value.filter(id => id !== widgetId);
  }
  emit('update', { enabledWidgets: [...enabledWidgets.value] });
};

const updateLayout = () => {
  emit('update', { layout: layout.value });
};

const updateTimeRange = () => {
  emit('update', { timeRange: timeRange.value });
};

const updateRefreshInterval = () => {
  emit('update', { refreshInterval: refreshInterval.value });
};

const reset = () => {
  layout.value = 'grid';
  enabledWidgets.value = availableWidgets
    .filter(w => w.defaultEnabled)
    .map(w => w.id);
  timeRange.value = 30;
  refreshInterval.value = 30;
  emit('update', {
    layout: layout.value,
    enabledWidgets: [...enabledWidgets.value],
    timeRange: timeRange.value,
    refreshInterval: refreshInterval.value,
  });
};

const save = () => {
  emit('save', {
    layout: layout.value,
    enabledWidgets: [...enabledWidgets.value],
    timeRange: timeRange.value,
    refreshInterval: refreshInterval.value,
  });
};

const close = () => {
  emit('close');
};
</script>

<style scoped>
.dashboard-customizer {
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  padding: 24px;
  max-width: 600px;
  max-height: 80vh;
  overflow-y: auto;
}

.customizer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  padding-bottom: 16px;
}

.customizer-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.close-btn {
  background: transparent;
  border: none;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  transition: all 0.2s;
  display: flex;
  align-items: center;
  justify-content: center;
}

.close-btn:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
}

.close-icon {
  width: 20px;
  height: 20px;
}

.customizer-content {
  display: flex;
  flex-direction: column;
  gap: 24px;
}

.section h3 {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.layout-options {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.layout-options label {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #a0aec0;
  cursor: pointer;
  padding: 8px;
  border-radius: 6px;
  transition: background 0.2s;
}

.layout-options label:hover {
  background: rgba(79, 172, 254, 0.1);
}

.layout-options input[type="radio"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.widgets-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.widget-item {
  padding: 12px;
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
}

.widget-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  margin-bottom: 4px;
}

.widget-checkbox input[type="checkbox"] {
  width: 18px;
  height: 18px;
  cursor: pointer;
}

.widget-label {
  font-weight: 500;
  color: #ffffff;
}

.widget-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin-left: 26px;
  margin-top: 4px;
}

.time-range-select,
.refresh-interval-select {
  width: 100%;
  padding: 10px 12px;
  background: rgba(26, 31, 46, 0.8);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.875rem;
  cursor: pointer;
}

.time-range-select:focus,
.refresh-interval-select:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.customizer-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
  margin-top: 24px;
  padding-top: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.btn-primary,
.btn-secondary {
  padding: 10px 20px;
  border-radius: 8px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
}

.btn-primary:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

.btn-secondary {
  background: transparent;
  color: #a0aec0;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border-color: rgba(79, 172, 254, 0.5);
}
</style>

