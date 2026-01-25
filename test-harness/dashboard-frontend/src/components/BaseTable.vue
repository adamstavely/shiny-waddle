<template>
  <div class="base-table-container" :class="containerClass">
    <div v-if="title || $slots.header" class="table-header">
      <div v-if="title || icon" class="table-title-group">
        <component v-if="icon" :is="icon" class="table-icon" />
        <h2 v-if="title" class="table-title">{{ title }}</h2>
      </div>
      <slot name="header" />
    </div>

    <div class="table-responsive" role="region" :aria-labelledby="title ? tableTitleId : undefined">
      <table class="base-table" :class="tableClass">
        <caption v-if="caption" class="sr-only">{{ caption }}</caption>
        <thead>
          <tr>
            <th
              v-for="(column, index) in columns"
              :key="column.key || index"
              :scope="column.headerScope || 'col'"
              :class="column.headerClass"
              :style="column.headerStyle"
            >
              <div class="th-content">
                {{ column.label }}
                <slot 
                  v-if="$slots[`header-${column.key}`]"
                  :name="`header-${column.key}`"
                  :column="column"
                />
              </div>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(row, rowIndex) in data"
            :key="getRowKey(row, rowIndex)"
            :class="getRowClass(row, rowIndex)"
            @click="handleRowClick(row, rowIndex, $event)"
          >
            <td
              v-for="(column, colIndex) in columns"
              :key="column.key || colIndex"
              :class="column.cellClass"
              :style="column.cellStyle"
            >
              <slot
                :name="`cell-${column.key}`"
                :row="row"
                :column="column"
                :value="row[column.key]"
                :rowIndex="rowIndex"
                :colIndex="colIndex"
              >
                {{ formatCellValue(row[column.key], column) }}
              </slot>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="data.length === 0" class="table-empty">
      <slot name="empty">
        <p>{{ emptyMessage }}</p>
      </slot>
    </div>

    <div v-if="$slots.footer" class="table-footer">
      <slot name="footer" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { type LucideIcon } from 'lucide-vue-next';
import { generateId } from '../utils/accessibility';

export interface TableColumn {
  key: string;
  label: string;
  headerScope?: 'col' | 'row';
  headerClass?: string;
  headerStyle?: Record<string, string>;
  cellClass?: string;
  cellStyle?: Record<string, string>;
  formatter?: (value: any, row: any) => string;
  align?: 'left' | 'center' | 'right';
}

interface Props {
  data: any[];
  columns: TableColumn[];
  title?: string;
  icon?: LucideIcon;
  caption?: string;
  emptyMessage?: string;
  rowKey?: string | ((row: any, index: number) => string | number);
  rowClass?: string | ((row: any, index: number) => string);
  clickable?: boolean;
  variant?: 'default' | 'striped' | 'bordered';
  size?: 'sm' | 'md' | 'lg';
}

const props = withDefaults(defineProps<Props>(), {
  emptyMessage: 'No data available',
  clickable: false,
  variant: 'default',
  size: 'md',
});

const emit = defineEmits<{
  'row-click': [row: any, index: number, event: MouseEvent];
}>();

const tableTitleId = generateId('table-title');

const containerClass = computed(() => ({
  [`table-${props.size}`]: true,
}));

const tableClass = computed(() => ({
  [`table-${props.variant}`]: true,
  'table-clickable': props.clickable,
}));

const getRowKey = (row: any, index: number): string | number => {
  if (typeof props.rowKey === 'function') {
    return props.rowKey(row, index);
  }
  if (typeof props.rowKey === 'string') {
    return row[props.rowKey];
  }
  return row.id || row.key || index;
};

const getRowClass = (row: any, index: number): string => {
  if (typeof props.rowClass === 'function') {
    return props.rowClass(row, index);
  }
  if (typeof props.rowClass === 'string') {
    return props.rowClass;
  }
  return '';
};

const formatCellValue = (value: any, column: TableColumn): string => {
  if (column.formatter) {
    return column.formatter(value, {});
  }
  if (value === null || value === undefined) {
    return '';
  }
  return String(value);
};

const handleRowClick = (row: any, index: number, event: MouseEvent) => {
  if (props.clickable) {
    emit('row-click', row, index, event);
  }
};
</script>

<style scoped>
.base-table-container {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
  overflow-x: auto;
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-lg);
  padding-bottom: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-primary);
}

.table-title-group {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
}

.table-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
  flex-shrink: 0;
}

.table-title {
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0;
}

.table-responsive {
  overflow-x: auto;
  width: 100%;
}

.base-table {
  width: 100%;
  border-collapse: collapse;
}

.base-table thead tr {
  background: var(--gradient-primary);
}

.base-table th {
  background: transparent;
  color: var(--color-text-primary);
  padding: var(--spacing-md);
  text-align: left;
  font-weight: var(--font-weight-semibold);
  font-size: var(--font-size-sm);
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.th-content {
  display: flex;
  align-items: center;
  gap: var(--spacing-xs);
}

.base-table td {
  padding: var(--spacing-md);
  border-bottom: var(--border-width-thin) solid var(--border-color-muted);
  color: var(--color-text-secondary);
  font-size: var(--font-size-base);
}

.base-table.table-striped tbody tr:nth-child(even) {
  background: var(--color-bg-overlay-light);
}

.base-table.table-bordered td,
.base-table.table-bordered th {
  border: var(--border-width-thin) solid var(--border-color-muted);
}

.base-table.table-clickable tbody tr {
  cursor: pointer;
  transition: var(--transition-base);
}

.base-table.table-clickable tbody tr:hover {
  background: var(--border-color-muted);
}

.base-table.table-sm th,
.base-table.table-sm td {
  padding: var(--spacing-sm);
  font-size: var(--font-size-sm);
}

.base-table.table-lg th,
.base-table.table-lg td {
  padding: var(--spacing-lg);
  font-size: var(--font-size-lg);
}

.table-empty {
  text-align: center;
  color: var(--color-text-muted);
  padding: var(--spacing-xl);
}

.table-footer {
  margin-top: var(--spacing-md);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
</style>
