<template>
  <div class="correlation-chart">
    <div class="correlation-matrix">
      <div
        v-for="(row, rowIndex) in matrixData"
        :key="`row-${rowIndex}`"
        class="matrix-row"
      >
        <div class="matrix-cell header" v-if="rowIndex === 0">
          <span></span>
        </div>
        <div
          v-for="(cell, colIndex) in row"
          :key="`cell-${rowIndex}-${colIndex}`"
          class="matrix-cell"
          :class="{
            header: colIndex === 0,
            diagonal: rowIndex === colIndex,
            high: cell.value >= 0.7,
            medium: cell.value >= 0.4 && cell.value < 0.7,
            low: cell.value < 0.4 && rowIndex !== colIndex
          }"
          :style="{
            backgroundColor: getCellColor(cell.value, rowIndex === colIndex)
          }"
        >
          <span v-if="colIndex === 0" class="cell-label">{{ cell.label }}</span>
          <span v-else-if="rowIndex === 0" class="cell-label">{{ cell.label }}</span>
          <span v-else class="cell-value">{{ cell.value.toFixed(2) }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';

interface Props {
  data: Array<{ violation1: string; violation2: string; correlation: number }>;
  height?: number;
}

const props = withDefaults(defineProps<Props>(), {
  height: 300
});

const allViolations = computed(() => {
  const violations = new Set<string>();
  props.data.forEach(item => {
    violations.add(item.violation1);
    violations.add(item.violation2);
  });
  return Array.from(violations);
});

const matrixData = computed(() => {
  const violations = allViolations.value;
  const matrix: Array<Array<{ label: string; value: number }>> = [];
  
  // Header row
  const headerRow: Array<{ label: string; value: number }> = [
    { label: '', value: 0 }
  ];
  violations.forEach(v => headerRow.push({ label: v.substring(0, 15), value: 0 }));
  matrix.push(headerRow);
  
  // Data rows
  violations.forEach((violation1, rowIndex) => {
    const row: Array<{ label: string; value: number }> = [
      { label: violation1.substring(0, 15), value: 0 }
    ];
    
    violations.forEach((violation2, colIndex) => {
      if (rowIndex === colIndex) {
        row.push({ label: '', value: 1 });
      } else {
        const correlation = props.data.find(
          d => (d.violation1 === violation1 && d.violation2 === violation2) ||
               (d.violation1 === violation2 && d.violation2 === violation1)
        );
        row.push({
          label: '',
          value: correlation ? correlation.correlation : 0
        });
      }
    });
    
    matrix.push(row);
  });
  
  return matrix;
});

const getCellColor = (value: number, isDiagonal: boolean): string => {
  if (isDiagonal) return 'rgba(79, 172, 254, 0.3)';
  if (value >= 0.7) return `rgba(252, 129, 129, ${0.3 + value * 0.5})`;
  if (value >= 0.4) return `rgba(251, 191, 36, ${0.2 + value * 0.4})`;
  return `rgba(34, 197, 94, ${0.1 + value * 0.3})`;
};
</script>

<style scoped>
.correlation-chart {
  width: 100%;
  height: 100%;
  overflow: auto;
}

.correlation-matrix {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.matrix-row {
  display: flex;
  gap: 2px;
}

.matrix-cell {
  min-width: 100px;
  min-height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 8px;
  border-radius: 4px;
  font-size: 11px;
  transition: all 0.2s;
}

.matrix-cell.header {
  background: rgba(15, 20, 25, 0.6) !important;
  font-weight: 600;
  color: #ffffff;
}

.matrix-cell.diagonal {
  background: rgba(79, 172, 254, 0.2) !important;
}

.matrix-cell .cell-label {
  font-size: 10px;
  color: #ffffff;
  text-align: center;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.matrix-cell .cell-value {
  font-size: 11px;
  font-weight: 600;
  color: #ffffff;
}

.matrix-cell:hover {
  transform: scale(1.05);
  z-index: 10;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}
</style>

