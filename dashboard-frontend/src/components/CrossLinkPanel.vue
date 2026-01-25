<template>
  <div class="cross-link-panel">
    <h3 class="panel-title">Where This Is Used</h3>
    <div v-if="loading" class="loading">Loading...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else class="links-container">
      <div v-if="usedInSuites.length > 0" class="link-group">
        <h4 class="link-group-title">Used in {{ usedInSuites.length }} Test Suite{{ usedInSuites.length !== 1 ? 's' : '' }}</h4>
        <div class="links-list">
          <router-link
            v-for="suite in usedInSuites"
            :key="suite.id"
            :to="`/tests/suites/${suite.id}`"
            class="link-item"
          >
            <List class="link-icon" />
            <span>{{ suite.name }}</span>
          </router-link>
        </div>
      </div>

      <div v-if="usedInHarnesses.length > 0" class="link-group">
        <h4 class="link-group-title">Used in {{ usedInHarnesses.length }} Test Harness{{ usedInHarnesses.length !== 1 ? 'es' : '' }}</h4>
        <div class="links-list">
          <router-link
            v-for="harness in usedInHarnesses"
            :key="harness.id"
            :to="`/tests/harnesses/${harness.id}`"
            class="link-item"
          >
            <Layers class="link-icon" />
            <span>{{ harness.name }}</span>
          </router-link>
        </div>
      </div>

      <div v-if="usedInBatteries.length > 0" class="link-group">
        <h4 class="link-group-title">Included in {{ usedInBatteries.length }} Test Batter{{ usedInBatteries.length !== 1 ? 'ies' : 'y' }}</h4>
        <div class="links-list">
          <router-link
            v-for="battery in usedInBatteries"
            :key="battery.id"
            :to="`/tests/batteries/${battery.id}`"
            class="link-item"
          >
            <Battery class="link-icon" />
            <span>{{ battery.name }}</span>
          </router-link>
        </div>
      </div>

      <div v-if="assignedToApplications.length > 0" class="link-group">
        <h4 class="link-group-title">Assigned to {{ assignedToApplications.length }} Application{{ assignedToApplications.length !== 1 ? 's' : '' }}</h4>
        <div class="links-list">
          <router-link
            v-for="app in assignedToApplications"
            :key="app.id"
            :to="`/applications/${app.id}`"
            class="link-item"
          >
            <Database class="link-icon" />
            <span>{{ app.name }}</span>
          </router-link>
        </div>
      </div>

      <div v-if="usedInSuites.length === 0 && usedInHarnesses.length === 0 && usedInBatteries.length === 0 && assignedToApplications.length === 0" class="empty-state">
        <p>Not used anywhere</p>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import axios from 'axios';
import { List, Layers, Battery, Database } from 'lucide-vue-next';

interface Props {
  entityType: 'test' | 'test-suite' | 'test-harness' | 'test-battery';
  entityId: string;
}

const props = defineProps<Props>();

const loading = ref(true);
const error = ref<string | null>(null);
const usedInSuites = ref<any[]>([]);
const usedInHarnesses = ref<any[]>([]);
const usedInBatteries = ref<any[]>([]);
const assignedToApplications = ref<any[]>([]);

const loadCrossLinks = async () => {
  try {
    loading.value = true;
    error.value = null;

    if (props.entityType === 'test') {
      const response = await axios.get(`/api/v1/tests/${props.entityId}/used-in-suites`);
      usedInSuites.value = response.data || [];
    } else if (props.entityType === 'test-suite') {
      const response = await axios.get(`/api/v1/test-suites/${props.entityId}/used-in-harnesses`);
      usedInHarnesses.value = response.data || [];
    } else if (props.entityType === 'test-harness') {
      const [harnessesResponse, appsResponse] = await Promise.all([
        axios.get(`/api/v1/test-harnesses/${props.entityId}/used-in-batteries`),
        axios.get(`/api/v1/test-harnesses/${props.entityId}/assigned-applications`),
      ]);
      usedInBatteries.value = harnessesResponse.data || [];
      assignedToApplications.value = appsResponse.data || [];
    } else if (props.entityType === 'test-battery') {
      const response = await axios.get(`/api/v1/test-batteries/${props.entityId}/assigned-applications`);
      assignedToApplications.value = response.data || [];
    }
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load cross-links';
    console.error('Error loading cross-links:', err);
  } finally {
    loading.value = false;
  }
};

onMounted(() => {
  loadCrossLinks();
});
</script>

<style scoped>
.cross-link-panel {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 20px;
  margin-top: 24px;
}

.panel-title {
  font-size: 1.125rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 16px 0;
}

.loading,
.error {
  text-align: center;
  padding: 20px;
  color: #a0aec0;
}

.error {
  color: #fc8181;
}

.links-container {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.link-group {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.link-group-title {
  font-size: 0.875rem;
  font-weight: 600;
  color: #a0aec0;
  margin: 0;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.links-list {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.link-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #4facfe;
  text-decoration: none;
  transition: all 0.2s;
  font-size: 0.875rem;
}

.link-item:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
  color: #ffffff;
}

.link-icon {
  width: 16px;
  height: 16px;
  flex-shrink: 0;
}

.empty-state {
  text-align: center;
  padding: 20px;
  color: #a0aec0;
  font-size: 0.875rem;
}
</style>

