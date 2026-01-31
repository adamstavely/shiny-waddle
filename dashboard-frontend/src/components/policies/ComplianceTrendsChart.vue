<template>
  <div class="compliance-trends-chart">
    <div class="chart-header">
      <h3>Compliance Trends</h3>
      <div class="chart-controls">
        <select v-model="timeRange" @change="loadTrends" class="time-range-select">
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
          <option value="90d">Last 90 Days</option>
          <option value="1y">Last Year</option>
        </select>
        <button @click="exportChart" class="btn-export">
          <Download class="icon" />
          Export
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Loading trends...</p>
    </div>

    <div v-else-if="error" class="error-state">
      <AlertTriangle class="error-icon" />
      <p>{{ error }}</p>
    </div>

    <div v-else-if="chartData" class="chart-container">
      <canvas ref="chartCanvas"></canvas>
    </div>

    <div v-else class="empty-state">
      <p>No trend data available for the selected period.</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, nextTick } from 'vue';
import { Chart, registerables } from 'chart.js';
import { Download, AlertTriangle } from 'lucide-vue-next';
import axios from 'axios';

Chart.register(...registerables);

interface TrendDataPoint {
  date: string;
  complianceScore: number;
  totalGaps: number;
  criticalGaps: number;
}

const chartCanvas = ref<HTMLCanvasElement | null>(null);
const timeRange = ref('30d');
const loading = ref(false);
const error = ref<string | null>(null);
const chartData = ref<TrendDataPoint[]>([]);
let chartInstance: Chart | null = null;

const loadTrends = async () => {
  loading.value = true;
  error.value = null;

  try {
    const response = await axios.get('/api/policies/compliance/trends', {
      params: { timeRange: timeRange.value },
      timeout: 10000,
    });

    chartData.value = response.data || [];
    await nextTick();
    renderChart();
  } catch (err: any) {
    error.value = err.response?.data?.message || err.message || 'Failed to load trends';
    console.error('Error loading trends:', err);
  } finally {
    loading.value = false;
  }
};

const renderChart = () => {
  if (!chartCanvas.value || !chartData.value.length) return;

  // Destroy existing chart
  if (chartInstance) {
    chartInstance.destroy();
  }

  const ctx = chartCanvas.value.getContext('2d');
  if (!ctx) return;

  // Prepare data
  const labels = chartData.value.map(d => {
    const date = new Date(d.date);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  });

  const complianceScores = chartData.value.map(d => d.complianceScore);
  const totalGaps = chartData.value.map(d => d.totalGaps);
  const criticalGaps = chartData.value.map(d => d.criticalGaps);

  chartInstance = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'Compliance Score (%)',
          data: complianceScores,
          borderColor: 'rgb(75, 192, 192)',
          backgroundColor: 'rgba(75, 192, 192, 0.2)',
          tension: 0.4,
          yAxisID: 'y',
          fill: true,
        },
        {
          label: 'Total Gaps',
          data: totalGaps,
          borderColor: 'rgb(255, 99, 132)',
          backgroundColor: 'rgba(255, 99, 132, 0.2)',
          tension: 0.4,
          yAxisID: 'y1',
        },
        {
          label: 'Critical Gaps',
          data: criticalGaps,
          borderColor: 'rgb(255, 159, 64)',
          backgroundColor: 'rgba(255, 159, 64, 0.2)',
          tension: 0.4,
          yAxisID: 'y1',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: {
        mode: 'index',
        intersect: false,
      },
      plugins: {
        legend: {
          position: 'top',
          labels: {
            color: 'var(--color-text-primary)',
            usePointStyle: true,
          },
        },
        tooltip: {
          backgroundColor: 'var(--color-bg-secondary)',
          titleColor: 'var(--color-text-primary)',
          bodyColor: 'var(--color-text-primary)',
          borderColor: 'var(--border-color-primary)',
          borderWidth: 1,
        },
      },
      scales: {
        x: {
          ticks: {
            color: 'var(--color-text-secondary)',
          },
          grid: {
            color: 'var(--border-color-primary)',
          },
        },
        y: {
          type: 'linear',
          display: true,
          position: 'left',
          min: 0,
          max: 100,
          ticks: {
            color: 'var(--color-text-secondary)',
            callback: function(value) {
              return value + '%';
            },
          },
          grid: {
            color: 'var(--border-color-primary)',
          },
          title: {
            display: true,
            text: 'Compliance Score (%)',
            color: 'var(--color-text-primary)',
          },
        },
        y1: {
          type: 'linear',
          display: true,
          position: 'right',
          ticks: {
            color: 'var(--color-text-secondary)',
          },
          grid: {
            drawOnChartArea: false,
          },
          title: {
            display: true,
            text: 'Number of Gaps',
            color: 'var(--color-text-primary)',
          },
        },
      },
    },
  });
};

const exportChart = () => {
  if (!chartInstance) return;

  const url = chartInstance.toBase64Image('image/png', 1.0);
  const link = document.createElement('a');
  link.href = url;
  link.download = `compliance-trends-${new Date().toISOString().split('T')[0]}.png`;
  link.click();
};

watch(timeRange, () => {
  loadTrends();
});

onMounted(() => {
  loadTrends();
});

onBeforeUnmount(() => {
  if (chartInstance) {
    chartInstance.destroy();
  }
});
</script>

<style scoped>
.compliance-trends-chart {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-md);
  padding: var(--spacing-lg);
  background: var(--color-bg-secondary);
  border-radius: var(--border-radius-lg);
  border: var(--border-width-thin) solid var(--border-color-primary);
}

.chart-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.chart-header h3 {
  margin: 0;
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
}

.chart-controls {
  display: flex;
  gap: var(--spacing-sm);
  align-items: center;
}

.time-range-select {
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-sm);
  cursor: pointer;
}

.btn-export {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
  padding: var(--spacing-sm) var(--spacing-md);
  background: var(--color-bg-overlay-light);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  cursor: pointer;
  font-size: var(--font-size-sm);
  transition: var(--transition-all);
}

.btn-export:hover {
  background: var(--border-color-muted);
  border-color: var(--color-primary);
}

.icon {
  width: 16px;
  height: 16px;
}

.chart-container {
  position: relative;
  height: 400px;
  width: 100%;
}

.loading-state,
.error-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  min-height: 300px;
  color: var(--color-text-secondary);
}

.loading-spinner {
  width: 40px;
  height: 40px;
  border: 3px solid var(--border-color-primary);
  border-top-color: var(--color-primary);
  border-radius: 50%;
  margin-bottom: var(--spacing-md);
  animation: spin 1s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.error-icon {
  width: 48px;
  height: 48px;
  color: var(--color-error);
  margin-bottom: var(--spacing-md);
}

.error-state {
  color: var(--color-error);
}
</style>
