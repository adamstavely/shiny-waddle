<template>
  <div class="admin-banners-tab">
    <div class="section-header">
      <div>
        <h2 class="section-title">
          <Megaphone class="title-icon" />
          Site Banners
        </h2>
        <p class="section-description">
          Manage site-wide notification banners displayed to all users
        </p>
      </div>
      <BaseButton label="Create Banner" :icon="Plus" @click="showBannerModal = true" />
    </div>

    <!-- Banners List -->
    <div v-if="loading" class="loading-state">
      <div class="loading">Loading banners...</div>
    </div>
    <div v-else-if="error" class="error-state">
      <div class="error">{{ error }}</div>
      <BaseButton label="Retry" @click="loadBanners" />
    </div>
    <div v-else-if="banners.length === 0" class="empty-state">
      <EmptyState
        title="No banners configured"
        description="Create a banner to display important messages to all users"
        :icon="Megaphone"
        action-label="Create Banner"
        :show-default-action="true"
        @action="showBannerModal = true"
      />
    </div>
    <div v-else class="banners-list">
      <div
        v-for="banner in banners"
        :key="banner.id"
        class="banner-card"
        :class="`banner-${banner.type}`"
      >
        <div class="banner-card-header">
          <div class="banner-card-title-row">
            <StatusBadge :status="banner.type" :label="banner.type.toUpperCase()" />
            <div class="banner-status-toggle">
              <label class="toggle-label">
                <input
                  type="checkbox"
                  :checked="banner.isActive"
                  @change="toggleBanner(banner.id)"
                  class="toggle-input"
                />
                <span class="toggle-slider"></span>
                <span class="toggle-text">{{ banner.isActive ? 'Active' : 'Inactive' }}</span>
              </label>
            </div>
          </div>
        </div>
        <div class="banner-card-content">
          <div class="banner-preview" :class="`preview-${banner.type}`">
            <div class="preview-content">
              <component :is="getBannerIcon(banner.type)" class="preview-icon" />
              <div class="preview-text">
                <p class="preview-message" v-html="banner.message"></p>
                <a
                  v-if="banner.linkUrl && banner.linkText"
                  :href="banner.linkUrl"
                  class="preview-link"
                >
                  {{ banner.linkText }}
                </a>
              </div>
            </div>
          </div>
          <div class="banner-card-details">
            <div class="detail-item">
              <span class="detail-label">Priority</span>
              <span class="detail-value">{{ banner.priority || 0 }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Dismissible</span>
              <span class="detail-value">{{ banner.dismissible ? 'Yes' : 'No' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Created</span>
              <span class="detail-value">{{ formatDate(banner.createdAt) }}</span>
            </div>
          </div>
        </div>
        <div class="banner-card-actions">
          <BaseButton label="Edit" :icon="Edit" variant="secondary" size="sm" @click="editBanner(banner)" />
          <BaseButton label="Delete" :icon="Trash2" variant="danger" size="sm" @click="deleteBanner(banner.id)" />
        </div>
      </div>
    </div>

    <!-- Banner Modal -->
    <BaseModal
      :isOpen="showBannerModal"
      :title="editingBanner ? 'Edit Banner' : 'Create Banner'"
      :icon="Megaphone"
      @update:isOpen="showBannerModal = $event"
      @close="closeBannerModal"
    >
      <BaseForm @submit="saveBanner" @cancel="closeBannerModal">
        <div class="form-row">
          <div class="form-group">
            <label>Banner Type *</label>
            <Dropdown
              v-model="bannerForm.type"
              :options="bannerTypeOptions"
              placeholder="Select type..."
            />
          </div>
          <div class="form-group">
            <label>Priority</label>
            <input
              v-model.number="bannerForm.priority"
              type="number"
              min="0"
              max="100"
              placeholder="0"
            />
            <small>Higher priority banners appear first</small>
          </div>
        </div>
        <div class="form-group">
          <label>Message *</label>
          <textarea
            v-model="bannerForm.message"
            rows="3"
            required
            placeholder="Enter banner message (HTML supported)..."
          ></textarea>
          <small>You can use HTML tags for formatting</small>
        </div>
        <div class="form-row">
          <div class="form-group">
            <label>Link URL (Optional)</label>
            <input
              v-model="bannerForm.linkUrl"
              type="url"
              placeholder="https://example.com"
            />
          </div>
          <div class="form-group">
            <label>Link Text (Optional)</label>
            <input
              v-model="bannerForm.linkText"
              type="text"
              placeholder="Learn more"
            />
          </div>
        </div>
        <div class="form-group">
          <label class="checkbox-label">
            <input
              v-model="bannerForm.dismissible"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Allow users to dismiss this banner</span>
          </label>
        </div>
        <div class="form-group">
          <label class="checkbox-label">
            <input
              v-model="bannerForm.isActive"
              type="checkbox"
              class="checkbox-input"
            />
            <span>Activate banner immediately</span>
          </label>
        </div>
        <template #footer>
          <BaseButton label="Cancel" variant="secondary" @click="closeBannerModal" />
          <BaseButton 
            :label="editingBanner ? 'Update' : 'Create' + ' Banner'" 
            type="submit"
            :disabled="!isBannerFormValid"
          />
        </template>
      </BaseForm>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  Megaphone,
  Plus,
  Edit,
  Trash2,
  Info,
  AlertTriangle,
  AlertCircle,
  CheckCircle2
} from 'lucide-vue-next';
import BaseButton from '../../components/BaseButton.vue';
import BaseModal from '../../components/BaseModal.vue';
import BaseForm from '../../components/BaseForm.vue';
import StatusBadge from '../../components/StatusBadge.vue';
import EmptyState from '../../components/EmptyState.vue';
import Dropdown from '../../components/Dropdown.vue';
import axios from 'axios';

const banners = ref<any[]>([]);
const loading = ref(false);
const error = ref<string | null>(null);
const showBannerModal = ref(false);
const editingBanner = ref<any>(null);

const bannerForm = ref({
  message: '',
  type: 'info' as 'info' | 'warning' | 'error' | 'success',
  dismissible: true,
  isActive: false,
  linkUrl: '',
  linkText: '',
  priority: 0
});

const bannerTypeOptions = computed(() => [
  { label: 'Info', value: 'info' },
  { label: 'Warning', value: 'warning' },
  { label: 'Error', value: 'error' },
  { label: 'Success', value: 'success' }
]);

const isBannerFormValid = computed(() => {
  return bannerForm.value.message.trim().length > 0;
});

const getBannerIcon = (type: string) => {
  switch (type) {
    case 'info':
      return Info;
    case 'warning':
      return AlertTriangle;
    case 'error':
      return AlertCircle;
    case 'success':
      return CheckCircle2;
    default:
      return Info;
  }
};

const loadBanners = async () => {
  try {
    loading.value = true;
    error.value = null;
    const response = await axios.get('/api/banners');
    banners.value = response.data.map((b: any) => ({
      ...b,
      createdAt: new Date(b.createdAt)
    }));
  } catch (err: any) {
    error.value = err.message || 'Failed to load banners';
    console.error('Error loading banners:', err);
  } finally {
    loading.value = false;
  }
};

const toggleBanner = async (id: string) => {
  try {
    const banner = banners.value.find(b => b.id === id);
    if (banner) {
      await axios.patch(`/api/banners/${id}`, { isActive: !banner.isActive });
      banner.isActive = !banner.isActive;
    }
  } catch (err: any) {
    console.error('Error toggling banner:', err);
    alert(err.response?.data?.message || 'Failed to toggle banner');
  }
};

const editBanner = (banner: any) => {
  editingBanner.value = banner;
  bannerForm.value = {
    message: banner.message,
    type: banner.type,
    dismissible: banner.dismissible,
    isActive: banner.isActive,
    linkUrl: banner.linkUrl || '',
    linkText: banner.linkText || '',
    priority: banner.priority || 0
  };
  showBannerModal.value = true;
};

const deleteBanner = async (id: string) => {
  if (!confirm('Are you sure you want to delete this banner?')) {
    return;
  }
  
  try {
    await axios.delete(`/api/banners/${id}`);
    await loadBanners();
  } catch (err: any) {
    console.error('Error deleting banner:', err);
    alert(err.response?.data?.message || 'Failed to delete banner');
  }
};

const saveBanner = async () => {
  try {
    if (editingBanner.value) {
      await axios.patch(`/api/banners/${editingBanner.value.id}`, bannerForm.value);
    } else {
      await axios.post('/api/banners', {
        ...bannerForm.value,
        createdAt: new Date()
      });
    }
    await loadBanners();
    closeBannerModal();
  } catch (err: any) {
    console.error('Error saving banner:', err);
    alert(err.response?.data?.message || 'Failed to save banner');
  }
};

const closeBannerModal = () => {
  showBannerModal.value = false;
  editingBanner.value = null;
  bannerForm.value = {
    message: '',
    type: 'info',
    dismissible: true,
    isActive: false,
    linkUrl: '',
    linkText: '',
    priority: 0
  };
};

const formatDate = (date: Date): string => {
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  });
};

onMounted(() => {
  loadBanners();
});
</script>

<style scoped>
.admin-banners-tab {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: var(--spacing-lg);
}

.section-title {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  font-size: var(--font-size-xl);
  font-weight: var(--font-weight-semibold);
  color: var(--color-text-primary);
  margin: 0 0 var(--spacing-xs) 0;
}

.title-icon {
  width: 24px;
  height: 24px;
  color: var(--color-primary);
}

.section-description {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
  margin: 0;
}

.banners-list {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-lg);
}

.banner-card {
  background: var(--gradient-card);
  border: var(--border-width-thin) solid var(--border-color-primary);
  border-radius: var(--border-radius-xl);
  padding: var(--spacing-lg);
}

.banner-card-header {
  margin-bottom: var(--spacing-md);
}

.banner-card-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.banner-status-toggle {
  display: flex;
  align-items: center;
}

.toggle-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  cursor: pointer;
}

.toggle-input {
  display: none;
}

.toggle-slider {
  width: 44px;
  height: 24px;
  background: var(--color-bg-overlay);
  border-radius: 12px;
  position: relative;
  transition: var(--transition-all);
}

.toggle-input:checked + .toggle-slider {
  background: var(--color-success);
}

.toggle-slider::after {
  content: '';
  position: absolute;
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: white;
  top: 2px;
  left: 2px;
  transition: var(--transition-all);
}

.toggle-input:checked + .toggle-slider::after {
  left: 22px;
}

.toggle-text {
  font-size: var(--font-size-sm);
  color: var(--color-text-secondary);
}

.banner-card-content {
  margin-bottom: var(--spacing-md);
}

.banner-preview {
  padding: var(--spacing-md);
  border-radius: var(--border-radius-md);
  margin-bottom: var(--spacing-md);
}

.preview-content {
  display: flex;
  gap: var(--spacing-sm);
  align-items: flex-start;
}

.preview-icon {
  width: 20px;
  height: 20px;
  flex-shrink: 0;
  margin-top: 2px;
}

.preview-text {
  flex: 1;
}

.preview-message {
  margin: 0 0 var(--spacing-xs) 0;
  color: var(--color-text-primary);
}

.preview-link {
  color: var(--color-primary);
  text-decoration: none;
  font-size: var(--font-size-sm);
}

.preview-link:hover {
  text-decoration: underline;
}

.banner-card-details {
  display: flex;
  gap: var(--spacing-lg);
  padding-top: var(--spacing-md);
  border-top: var(--border-width-thin) solid var(--border-color-primary);
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.detail-label {
  font-size: var(--font-size-xs);
  color: var(--color-text-secondary);
}

.detail-value {
  font-size: var(--font-size-sm);
  color: var(--color-text-primary);
  font-weight: var(--font-weight-medium);
}

.banner-card-actions {
  display: flex;
  gap: var(--spacing-sm);
  justify-content: flex-end;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: var(--spacing-md);
}

.form-group {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.form-group label {
  font-size: var(--font-size-sm);
  font-weight: var(--font-weight-medium);
  color: var(--color-text-primary);
}

.form-group input,
.form-group textarea {
  padding: var(--spacing-sm);
  background: var(--color-bg-overlay);
  border: var(--border-width-thin) solid var(--border-color-secondary);
  border-radius: var(--border-radius-md);
  color: var(--color-text-primary);
  font-size: var(--font-size-base);
}

.form-group small {
  font-size: var(--font-size-xs);
  color: var(--color-text-muted);
}

.checkbox-label {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm);
  cursor: pointer;
}

.checkbox-input {
  width: 18px;
  height: 18px;
  cursor: pointer;
}
</style>
