<template>
  <Teleport to="body">
    <Transition name="fade">
      <div v-if="show && contract" class="modal-overlay" @click="close">
        <div class="modal-content" @click.stop>
          <div class="modal-header">
            <div class="modal-title-group">
              <History class="modal-title-icon" />
              <h2>Contract Versions: {{ contract.name }}</h2>
            </div>
            <button @click="close" class="modal-close">
              <X class="close-icon" />
            </button>
          </div>
          <div class="modal-body">
            <div class="versions-list">
              <div
                v-for="version in contractVersions"
                :key="version.version"
                class="version-item"
                :class="{ active: version.version === contract.version }"
              >
                <div class="version-header">
                  <div>
                    <span class="version-number">v{{ version.version }}</span>
                    <span class="version-status" :class="`status-${version.status}`">
                      {{ version.status }}
                    </span>
                  </div>
                  <span class="version-date">{{ formatDate(version.createdAt) }}</span>
                </div>
                <div class="version-changes" v-if="version.changes">
                  <div class="changes-label">Changes:</div>
                  <div class="changes-list">
                    <div v-for="(change, index) in version.changes" :key="index" class="change-item">
                      {{ change }}
                    </div>
                  </div>
                </div>
                <div class="version-actions">
                  <button @click="viewVersion(version.version)" class="btn-small">View</button>
                  <button @click="compareVersions(version.version)" class="btn-small">Compare</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue';
import { Teleport } from 'vue';
import { History, X } from 'lucide-vue-next';

interface Props {
  show: boolean;
  contract: any;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  close: [];
}>();

const contractVersions = computed(() => {
  if (!props.contract) return [];
  // Generate version history
  const versions = [];
  for (let v = props.contract.version; v >= 1; v--) {
    versions.push({
      version: v,
      status: v === props.contract.version ? 'active' : 'deprecated',
      createdAt: new Date(Date.now() - (props.contract.version - v) * 7 * 24 * 60 * 60 * 1000),
      changes: v > 1 ? [`Updated requirement ${v - 1}`, 'Modified enforcement rules'] : ['Initial version']
    });
  }
  return versions;
});

function close() {
  emit('close');
}

function formatDate(date: Date): string {
  return new Date(date).toLocaleDateString();
}

function viewVersion(version: number) {
  console.log('View version:', version);
}

function compareVersions(version: number) {
  console.log('Compare with version:', version);
}
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
  max-width: 700px;
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
  flex-shrink: 0;
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

.versions-list {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.version-item {
  padding: 16px;
  background: rgba(15, 20, 25, 0.4);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  transition: all 0.2s;
}

.version-item.active {
  border-color: #4facfe;
  background: rgba(79, 172, 254, 0.1);
}

.version-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
}

.version-number {
  font-size: 1.1rem;
  font-weight: 600;
  color: #4facfe;
  margin-right: 12px;
}

.version-status {
  padding: 4px 10px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.status-active {
  background: rgba(34, 197, 94, 0.2);
  color: #22c55e;
}

.status-deprecated {
  background: rgba(252, 129, 129, 0.2);
  color: #fc8181;
}

.version-date {
  font-size: 0.875rem;
  color: #a0aec0;
}

.version-changes {
  margin-bottom: 12px;
}

.changes-label {
  font-size: 0.75rem;
  color: #718096;
  margin-bottom: 8px;
}

.changes-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.change-item {
  font-size: 0.875rem;
  color: #a0aec0;
  padding-left: 12px;
  position: relative;
}

.change-item::before {
  content: '•';
  position: absolute;
  left: 0;
  color: #4facfe;
}

.version-actions {
  display: flex;
  gap: 8px;
}

.btn-small {
  padding: 6px 12px;
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 6px;
  color: #4facfe;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
}

.btn-small:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
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

