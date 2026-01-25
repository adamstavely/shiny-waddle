<template>
  <div class="risk-heatmap" role="img" :aria-label="`Risk heatmap showing ${rows.length} applications and ${columns.length} categories`">
    <div class="heatmap-header">
      <h3 class="heatmap-title">{{ title }}</h3>
      <div class="heatmap-legend">
        <span class="legend-label">Low</span>
        <div class="legend-gradient"></div>
        <span class="legend-label">High</span>
      </div>
    </div>
    
    <div class="heatmap-container" ref="containerRef">
      <div class="heatmap-labels">
        <div class="row-labels">
          <div
            v-for="(row, index) in rows"
            :key="index"
            class="row-label"
            :title="row.label"
          >
            {{ row.label }}
          </div>
        </div>
      </div>
      
      <div class="heatmap-grid">
        <div class="column-labels">
          <div
            v-for="(col, index) in columns"
            :key="index"
            class="column-label"
            :title="col.label"
          >
            {{ col.label }}
          </div>
        </div>
        
        <div class="heatmap-cells">
          <div
            v-for="(cell, index) in cells"
            :key="index"
            class="heatmap-cell"
            :class="getCellClass(cell.value)"
            :style="getCellStyle(cell.value)"
            :title="getCellTooltip(cell)"
            @mouseenter="handleCellHover(cell, $event)"
            @mouseleave="handleCellLeave"
            @click="handleCellClick(cell)"
            role="button"
            :aria-label="getCellTooltip(cell)"
            tabindex="0"
            @keydown.enter="handleCellClick(cell)"
            @keydown.space.prevent="handleCellClick(cell)"
          >
            <span class="cell-value">{{ formatValue(cell.value) }}</span>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Tooltip -->
    <div
      v-if="hoveredCell"
      class="heatmap-tooltip"
      :style="tooltipStyle"
    >
      <div class="tooltip-header">
        <strong>{{ hoveredCell.rowLabel }}</strong> - {{ hoveredCell.colLabel }}
      </div>
      <div class="tooltip-content">
        <div class="tooltip-value">
          Risk Score: <strong>{{ formatValue(hoveredCell.value) }}</strong>
        </div>
        <div v-if="hoveredCell.metadata" class="tooltip-metadata">
          <div v-for="(value, key) in hoveredCell.metadata" :key="key" class="tooltip-item">
            {{ key }}: {{ value }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onBeforeUnmount } from 'vue';

export interface HeatmapCell {
  rowIndex: number;
  colIndex: number;
  value: number;
  rowLabel: string;
  colLabel: string;
  metadata?: Record<string, any>;
}

interface Props {
  data: Record<string, Record<string, number>>; // { application: { category: score } }
  title?: string;
  minValue?: number;
  maxValue?: number;
  colorScheme?: 'red-yellow-green' | 'blue' | 'purple';
}

const props = withDefaults(defineProps<Props>(), {
  title: 'Risk Heatmap',
  minValue: 0,
  maxValue: 100,
  colorScheme: 'red-yellow-green',
});

const emit = defineEmits<{
  cellClick: [cell: HeatmapCell];
}>();

const containerRef = ref<HTMLElement>();
const hoveredCell = ref<HeatmapCell | null>(null);
const tooltipStyle = ref<{ top: string; left: string }>({ top: '0px', left: '0px' });

const rows = computed(() => {
  return Object.keys(props.data).map((key, index) => ({
    key,
    label: key,
    index,
  }));
});

const columns = computed(() => {
  const allColumns = new Set<string>();
  Object.values(props.data).forEach((categories) => {
    Object.keys(categories).forEach((cat) => allColumns.add(cat));
  });
  return Array.from(allColumns).map((key, index) => ({
    key,
    label: key,
    index,
  }));
});

const cells = computed((): HeatmapCell[] => {
  const result: HeatmapCell[] = [];
  rows.value.forEach((row) => {
    columns.value.forEach((col) => {
      const value = props.data[row.key]?.[col.key] ?? 0;
      result.push({
        rowIndex: row.index,
        colIndex: col.index,
        value,
        rowLabel: row.label,
        colLabel: col.label,
        metadata: {
          application: row.label,
          category: col.label,
        },
      });
    });
  });
  return result;
});

const getCellClass = (value: number): string => {
  const normalized = (value - props.minValue) / (props.maxValue - props.minValue);
  if (normalized < 0.33) return 'risk-low';
  if (normalized < 0.66) return 'risk-medium';
  return 'risk-high';
};

const getCellStyle = (value: number): Record<string, string> => {
  const normalized = Math.max(0, Math.min(1, (value - props.minValue) / (props.maxValue - props.minValue)));
  
  if (props.colorScheme === 'red-yellow-green') {
    // Red (high risk) to Yellow to Green (low risk)
    const hue = normalized < 0.5 
      ? 120 - (normalized * 2 * 60) // Green to Yellow
      : 60 - ((normalized - 0.5) * 2 * 60); // Yellow to Red
    return {
      backgroundColor: `hsl(${hue}, 70%, ${50 - normalized * 20}%)`,
      opacity: `${0.6 + normalized * 0.4}`,
    };
  } else if (props.colorScheme === 'blue') {
    return {
      backgroundColor: `hsl(200, 70%, ${50 - normalized * 30}%)`,
      opacity: `${0.5 + normalized * 0.5}`,
    };
  } else {
    // purple
    return {
      backgroundColor: `hsl(${270 - normalized * 60}, 70%, ${50 - normalized * 20}%)`,
      opacity: `${0.6 + normalized * 0.4}`,
    };
  }
};

const formatValue = (value: number): string => {
  return value.toFixed(1);
};

const getCellTooltip = (cell: HeatmapCell): string => {
  return `${cell.rowLabel} - ${cell.colLabel}: ${formatValue(cell.value)}`;
};

const handleCellHover = (cell: HeatmapCell, event: MouseEvent) => {
  hoveredCell.value = cell;
  updateTooltipPosition(event);
};

const handleCellLeave = () => {
  hoveredCell.value = null;
};

const handleCellClick = (cell: HeatmapCell) => {
  emit('cellClick', cell);
};

const updateTooltipPosition = (event: MouseEvent) => {
  if (!containerRef.value) return;
  
  const rect = containerRef.value.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  
  tooltipStyle.value = {
    top: `${y + 10}px`,
    left: `${x + 10}px`,
  };
};

const handleMouseMove = (event: MouseEvent) => {
  if (hoveredCell.value && containerRef.value?.contains(event.target as Node)) {
    updateTooltipPosition(event);
  }
};

onMounted(() => {
  document.addEventListener('mousemove', handleMouseMove);
});

onBeforeUnmount(() => {
  document.removeEventListener('mousemove', handleMouseMove);
});
</script>

<style scoped>
.risk-heatmap {
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 24px;
  border: 1px solid rgba(79, 172, 254, 0.2);
  position: relative;
}

.heatmap-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
}

.heatmap-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0;
}

.heatmap-legend {
  display: flex;
  align-items: center;
  gap: 8px;
}

.legend-label {
  font-size: 0.75rem;
  color: #a0aec0;
}

.legend-gradient {
  width: 120px;
  height: 12px;
  background: linear-gradient(to right, #22c55e, #fbbf24, #fc8181);
  border-radius: 6px;
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.heatmap-container {
  overflow-x: auto;
  overflow-y: auto;
  max-height: 600px;
}

.heatmap-labels {
  margin-bottom: 8px;
}

.row-labels {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.row-label {
  padding: 8px 12px;
  font-size: 0.875rem;
  color: #a0aec0;
  text-align: right;
  min-width: 150px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.heatmap-grid {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.column-labels {
  display: flex;
  gap: 4px;
  margin-left: 150px;
  margin-bottom: 8px;
}

.column-label {
  padding: 8px 12px;
  font-size: 0.875rem;
  color: #a0aec0;
  text-align: center;
  min-width: 100px;
  writing-mode: vertical-rl;
  text-orientation: mixed;
  white-space: nowrap;
}

.heatmap-cells {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
  gap: 4px;
  margin-left: 150px;
}

.heatmap-cell {
  aspect-ratio: 1;
  min-width: 80px;
  min-height: 80px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  border: 2px solid rgba(79, 172, 254, 0.2);
  cursor: pointer;
  transition: all 0.2s;
  position: relative;
}

.heatmap-cell:hover {
  border-color: #4facfe;
  transform: scale(1.05);
  z-index: 10;
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.3);
}

.heatmap-cell:focus {
  outline: 3px solid #4facfe;
  outline-offset: 2px;
}

.cell-value {
  font-size: 0.875rem;
  font-weight: 600;
  color: #ffffff;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.5);
}

.risk-low {
  border-color: rgba(34, 197, 94, 0.3);
}

.risk-medium {
  border-color: rgba(251, 191, 36, 0.3);
}

.risk-high {
  border-color: rgba(252, 129, 129, 0.3);
}

.heatmap-tooltip {
  position: absolute;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  padding: 12px;
  pointer-events: none;
  z-index: 1000;
  min-width: 200px;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}

.tooltip-header {
  font-size: 0.875rem;
  font-weight: 600;
  color: #4facfe;
  margin-bottom: 8px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.2);
  padding-bottom: 8px;
}

.tooltip-content {
  font-size: 0.8rem;
  color: #a0aec0;
}

.tooltip-value {
  margin-bottom: 8px;
}

.tooltip-value strong {
  color: #ffffff;
  font-weight: 600;
}

.tooltip-metadata {
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid rgba(79, 172, 254, 0.1);
}

.tooltip-item {
  margin: 4px 0;
  font-size: 0.75rem;
}

/* Responsive */
@media (max-width: 768px) {
  .heatmap-container {
    max-height: 400px;
  }
  
  .row-label {
    min-width: 100px;
    font-size: 0.75rem;
  }
  
  .column-label {
    min-width: 60px;
    font-size: 0.75rem;
  }
  
  .heatmap-cell {
    min-width: 60px;
    min-height: 60px;
  }
  
  .cell-value {
    font-size: 0.75rem;
  }
}
</style>

