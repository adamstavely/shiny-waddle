<template>
  <div class="table-container">
    <h2>Recent Test Results</h2>
    <table v-if="results.length > 0">
      <thead>
        <tr>
          <th>Test Name</th>
          <th>Type</th>
          <th>Status</th>
          <th>Timestamp</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="(result, index) in results.slice(0, 10)" :key="index">
          <td>{{ result.testName }}</td>
          <td>{{ result.testType }}</td>
          <td>
            <span
              :class="['status-badge', result.passed ? 'status-passed' : 'status-failed']"
            >
              {{ result.passed ? 'PASSED' : 'FAILED' }}
            </span>
          </td>
          <td>{{ formatDate(result.timestamp) }}</td>
        </tr>
      </tbody>
    </table>
    <div v-else class="empty">No test results available</div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  results: any[];
}>();

const formatDate = (timestamp: string | Date): string => {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  return date.toLocaleString();
};
</script>

<style scoped>
.table-container {
  background: linear-gradient(135deg, #1a2332 0%, #2d3748 100%);
  border-radius: 12px;
  padding: 30px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  overflow-x: auto;
}

.table-container h2 {
  margin-bottom: 20px;
  color: #ffffff;
  font-weight: 600;
}

table {
  width: 100%;
  border-collapse: collapse;
}

th {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  padding: 15px;
  text-align: left;
  font-weight: 600;
}

td {
  padding: 15px;
  border-bottom: 1px solid rgba(79, 172, 254, 0.1);
  color: #a0aec0;
}

tr:hover {
  background: rgba(79, 172, 254, 0.05);
}

.status-badge {
  display: inline-block;
  padding: 5px 15px;
  border-radius: 20px;
  font-size: 0.9em;
  font-weight: 600;
}

.status-passed {
  background: rgba(72, 187, 120, 0.2);
  color: #48bb78;
  border: 1px solid rgba(72, 187, 120, 0.3);
}

.status-failed {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
  border: 1px solid rgba(252, 129, 129, 0.3);
}

.empty {
  text-align: center;
  color: #718096;
  padding: 40px;
}
</style>

