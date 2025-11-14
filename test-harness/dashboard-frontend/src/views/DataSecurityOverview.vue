<template>
  <div class="data-security-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Data Security
              <span class="hero-subtitle">Data Protection & Contracts</span>
            </h1>
            <p class="hero-description">
              Manage datasets, configure data contracts, and ensure proper data protection. 
              Define data access restrictions, configure privacy requirements, and establish 
              contracts that govern how data can be used, exported, and shared across your organization.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/datasets')" class="btn-primary">Manage Datasets</button>
              <button @click="navigateTo('/contracts')" class="btn-secondary">View Contracts</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="data-security-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="dataGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:1" />
                  </linearGradient>
                </defs>
                
                <!-- Database -->
                <ellipse cx="125" cy="60" rx="50" ry="15" fill="url(#dataGradient)" opacity="0.3" stroke="url(#dataGradient)" stroke-width="2"/>
                <rect x="75" y="60" width="100" height="80" rx="0" fill="url(#dataGradient)" opacity="0.2" stroke="url(#dataGradient)" stroke-width="2"/>
                <ellipse cx="125" cy="140" rx="50" ry="15" fill="url(#dataGradient)" opacity="0.3" stroke="url(#dataGradient)" stroke-width="2"/>
                
                <!-- Data rows -->
                <line x1="85" y1="75" x2="165" y2="75" stroke="#00f2fe" stroke-width="2" opacity="0.6"/>
                <line x1="85" y1="90" x2="165" y2="90" stroke="#00f2fe" stroke-width="2" opacity="0.6"/>
                <line x1="85" y1="105" x2="165" y2="105" stroke="#00f2fe" stroke-width="2" opacity="0.6"/>
                <line x1="85" y1="120" x2="165" y2="120" stroke="#00f2fe" stroke-width="2" opacity="0.6"/>
                
                <!-- Lock icon -->
                <rect x="110" y="155" width="30" height="25" rx="4" fill="url(#dataGradient)" opacity="0.4" stroke="url(#dataGradient)" stroke-width="2"/>
                <path d="M 115 155 L 115 145 Q 115 140, 125 140 Q 135 140, 135 145 L 135 155" 
                      stroke="url(#dataGradient)" 
                      stroke-width="2" 
                      fill="none" 
                      opacity="0.8"/>
                
                <!-- Contract document -->
                <rect x="30" y="100" width="40" height="50" rx="4" fill="url(#dataGradient)" opacity="0.3" stroke="url(#dataGradient)" stroke-width="2"/>
                <line x1="38" y1="115" x2="62" y2="115" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                <line x1="38" y1="125" x2="58" y2="125" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                <line x1="38" y1="135" x2="62" y2="135" stroke="#00f2fe" stroke-width="2" opacity="0.8"/>
                
                <!-- Shield -->
                <path d="M 180 100 L 220 115 L 220 145 L 180 160 L 140 145 L 140 115 Z" 
                      fill="url(#dataGradient)" 
                      opacity="0.3" 
                      stroke="url(#dataGradient)" 
                      stroke-width="2"/>
                <path d="M 180 105 L 215 118 L 215 142 L 180 155 L 145 142 L 145 118 Z" 
                      fill="url(#dataGradient)" 
                      opacity="0.4" 
                      stroke="url(#dataGradient)" 
                      stroke-width="1.5"/>
                
                <!-- Connection lines -->
                <line x1="70" y1="125" x2="100" y2="100" stroke="url(#dataGradient)" stroke-width="2" opacity="0.5"/>
                <line x1="180" y1="130" x2="150" y2="100" stroke="url(#dataGradient)" stroke-width="2" opacity="0.5"/>
                
                <!-- Checkmark -->
                <path d="M 40 120 L 48 128 L 62 110" stroke="#00f2fe" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.9"/>
                
                <!-- Accent dots -->
                <circle cx="125" cy="30" r="3" fill="#00f2fe" opacity="0.8"/>
                <circle cx="50" cy="125" r="2.5" fill="#4facfe" opacity="0.7"/>
                <circle cx="200" cy="130" r="2.5" fill="#4facfe" opacity="0.7"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- How It Works Section -->
    <div class="how-it-works-section">
      <h2 class="section-title">How It Works</h2>
      <p class="section-description">
        Understand how to manage data security and protection
      </p>
      
      <div class="explanation-grid">
        <div class="explanation-card">
          <div class="explanation-icon">
            <Database />
          </div>
          <h3 class="explanation-title">Datasets</h3>
          <p class="explanation-text">
            Manage datasets and configure their security attributes. Define data classification 
            levels, sensitivity ratings, and access restrictions. Datasets represent the data 
            resources that need protection and are used in access control policy evaluation.
          </p>
          <button @click="navigateTo('/datasets')" class="explanation-link">Manage Datasets →</button>
        </div>
        
        <div class="explanation-card">
          <div class="explanation-icon">
            <FileCheck />
          </div>
          <h3 class="explanation-title">Contracts</h3>
          <p class="explanation-text">
            Define data contracts that specify how data can be used, exported, and shared. 
            Contracts enforce restrictions on data operations, set minimum aggregation thresholds, 
            and control field-level access to ensure compliance with data protection requirements.
          </p>
          <button @click="navigateTo('/contracts')" class="explanation-link">View Contracts →</button>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card">
          <Database class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.datasets || 0 }}</div>
            <div class="stat-label">Datasets</div>
          </div>
        </div>
        <div class="stat-card">
          <FileCheck class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.contracts || 0 }}</div>
            <div class="stat-label">Contracts</div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { Database, FileCheck } from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Data Security', to: '/data-security' },
];

const stats = ref({
  datasets: 0,
  contracts: 0,
});

const navigateTo = (path: string) => {
  router.push(path);
};

const loadStats = async () => {
  try {
    // Load datasets count
    const datasetsRes = await axios.get('/api/datasets');
    stats.value.datasets = datasetsRes.data?.length || 0;
    
    // Load contracts count
    const contractsRes = await axios.get('/api/contracts');
    stats.value.contracts = contractsRes.data?.length || 0;
  } catch (error) {
    console.error('Failed to load stats:', error);
  }
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.data-security-overview-page {
  width: 100%;
  max-width: 1400px;
  margin: 0 auto;
  padding: 24px;
}

.hero-section {
  margin-bottom: 3rem;
}

.hero-card {
  position: relative;
  border-radius: 24px;
  padding: 48px 64px;
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 50%, #1a1f2e 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  box-shadow: 0 20px 60px rgba(0, 0, 0, 0.4);
  overflow: hidden;
}

.hero-background {
  position: absolute;
  inset: 0;
  opacity: 0.1;
  background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
}

.hero-content {
  position: relative;
  z-index: 10;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 64px;
  align-items: center;
}

.hero-text {
  flex: 1;
}

.hero-title {
  font-size: 4rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 16px;
  line-height: 1.1;
  letter-spacing: -1px;
}

.hero-subtitle {
  display: block;
  font-size: 2rem;
  margin-top: 12px;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  font-weight: 600;
}

.hero-description {
  font-size: 1.125rem;
  color: #a0aec0;
  line-height: 1.6;
  margin-bottom: 32px;
}

.hero-actions {
  display: flex;
  gap: 16px;
}

.btn-primary,
.btn-secondary {
  padding: 12px 24px;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.3);
}

.btn-secondary {
  background: rgba(79, 172, 254, 0.1);
  color: #4facfe;
  border: 1px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.2);
  border-color: rgba(79, 172, 254, 0.5);
}

.hero-visual {
  display: flex;
  justify-content: center;
  align-items: center;
}

.svg-container {
  width: 100%;
  max-width: 400px;
}

.data-security-svg {
  width: 100%;
  height: auto;
}

.how-it-works-section {
  margin-bottom: 3rem;
}

.section-title {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 8px;
}

.section-description {
  font-size: 1.125rem;
  color: #a0aec0;
  margin-bottom: 2rem;
}

.explanation-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.5rem;
}

.explanation-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.2s;
}

.explanation-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.explanation-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  margin-bottom: 1rem;
}

.explanation-title {
  font-size: 1.25rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.75rem;
}

.explanation-text {
  font-size: 0.95rem;
  color: #a0aec0;
  line-height: 1.6;
  margin-bottom: 1rem;
}

.explanation-link {
  color: #4facfe;
  font-size: 0.9rem;
  font-weight: 500;
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  transition: all 0.2s;
}

.explanation-link:hover {
  color: #00f2fe;
}

.stats-section {
  margin-bottom: 3rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.stat-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  transition: all 0.2s;
}

.stat-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.stat-icon {
  width: 48px;
  height: 48px;
  color: #4facfe;
  flex-shrink: 0;
}

.stat-content {
  flex: 1;
}

.stat-value {
  font-size: 2rem;
  font-weight: 700;
  color: #ffffff;
  line-height: 1;
  margin-bottom: 0.25rem;
}

.stat-label {
  font-size: 0.875rem;
  color: #a0aec0;
}

@media (max-width: 768px) {
  .hero-content {
    grid-template-columns: 1fr;
    gap: 2rem;
  }
  
  .hero-title {
    font-size: 2rem;
  }
  
  .hero-visual {
    order: -1;
  }
}
</style>

