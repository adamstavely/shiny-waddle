<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="isOpen" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <h2>Attach Test Battery</h2>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div v-if="loading" class="loading-state">
              <p>Loading batteries...</p>
            </div>
            <div v-else-if="error" class="error-state">
              <p>{{ error }}</p>
            </div>
            <div v-else>
              <input
                v-model="searchQuery"
                type="text"
                placeholder="Search batteries..."
                class="search-input"
              />
              <div v-if="filteredBatteries.length === 0" class="empty-state">
                <p>{{ searchQuery ? 'No batteries match your search' : 'No available batteries' }}</p>
              </div>
              <div v-else class="batteries-list">
                <div
                  v-for="battery in filteredBatteries"
                  :key="battery.id"
                  class="battery-option"
                  @click="attachBattery(battery.id)"
                >
                  <div class="battery-info">
                    <h4 class="battery-name">{{ battery.name }}</h4>
                    <p v-if="battery.description" class="battery-description">{{ battery.description }}</p>
                    <div class="battery-meta">
                      <span>{{ battery.harnessIds?.length || 0 }} harnesses</span>
                      <span v-if="battery.team"> • {{ battery.team }}</span>
                    </div>
                  </div>
                  <Check class="check-icon" />
                </div>
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button @click="close" class="btn-secondary">Cancel</button>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue';
import { Teleport, Transition } from 'vue';
import { X, Check } from 'lucide-vue-next';
import axios from 'axios';

interface Props {
  isOpen: boolean;
  applicationId: string;
  assignedBatteryIds?: string[];
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
  attached: [batteryId: string];
}>();

const loading = ref(false);
const error = ref<string | null>(null);
const batteries = ref<any[]>([]);
const searchQuery = ref('');

const filteredBatteries = computed(() => {
  let filtered = batteries.value;
  
  // Filter out already assigned batteries
  if (props.assignedBatteryIds && props.assignedBatteryIds.length > 0) {
    filtered = filtered.filter(b => !props.assignedBatteryIds!.includes(b.id));
  }
  
  // Filter by search query
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase();
    filtered = filtered.filter(b =>
      b.name.toLowerCase().includes(query) ||
      (b.description && b.description.toLowerCase().includes(query))
    );
  }
  
  return filtered;
});

const loadBatteries = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/v1/test-batteries');
    batteries.value = response.data || [];
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to load batteries';
    console.error('Error loading batteries:', err);
  } finally {
    loading.value = false;
  }
};

const attachBattery = async (batteryId: string) => {
  try {
    loading.value = true;
    // Attach battery to application by assigning all harnesses from the battery
    // First, get the battery to find its harnesses
    const batteryResponse = await axios.get(`/api/v1/test-batteries/${batteryId}`);
    const battery = batteryResponse.data;
    
    if (battery.harnessIds && battery.harnessIds.length > 0) {
      // Assign all harnesses in the battery to the application
      for (const harnessId of battery.harnessIds) {
        await axios.post(`/api/v1/test-harnesses/${harnessId}/applications`, {
          applicationId: props.applicationId
        });
      }
    }
    
    emit('attached', batteryId);
    close();
  } catch (err: any) {
    error.value = err.response?.data?.message || 'Failed to attach battery';
    console.error('Error attaching battery:', err);
    alert('Failed to attach battery. Please try again.');
  } finally {
    loading.value = false;
  }
};

const close = () => {
  emit('close');
  searchQuery.value = '';
  error.value = null;
};

watch(() => props.isOpen, (newValue) => {
  if (newValue) {
    loadBatteries();
  }
});

onMounted(() => {
  if (props.isOpen) {
    loadBatteries();
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
  background: rgba(0, 0, 0, 0.7);
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
  max-height: 80vh;
  display: flex;
  flex-direction: column;
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
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
  border-radius: 6px;
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
  flex: 1;
  padding: 24px;
  overflow-y: auto;
}

.search-input {
  width: 100%;
  padding: 12px 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  color: #ffffff;
  font-size: 0.9rem;
  margin-bottom: 16px;
  transition: all 0.2s;
}

.search-input:focus {
  outline: none;
  border-color: #4facfe;
  box-shadow: 0 0 0 3px rgba(79, 172, 254, 0.1);
}

.batteries-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.battery-option {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 16px;
  background: rgba(15, 20, 25, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.battery-option:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.4);
}

.battery-info {
  flex: 1;
}

.battery-name {
  font-size: 1rem;
  font-weight: 600;
  color: #ffffff;
  margin: 0 0 4px 0;
}

.battery-description {
  font-size: 0.875rem;
  color: #a0aec0;
  margin: 0 0 8px 0;
}

.battery-meta {
  font-size: 0.75rem;
  color: #718096;
}

.check-icon {
  width: 20px;
  height: 20px;
  color: #4facfe;
  flex-shrink: 0;
  opacity: 0;
  transition: opacity 0.2s;
}

.battery-option:hover .check-icon {
  opacity: 1;
}

.loading-state,
.error-state,
.empty-state {
  text-align: center;
  padding: 40px;
  color: #a0aec0;
}

.error-state {
  color: #fc8181;
}

.modal-footer {
  padding: 24px;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

.btn-secondary {
  padding: 10px 20px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 8px;
  color: #4facfe;
  cursor: pointer;
  font-weight: 500;
  transition: all 0.2s;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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

