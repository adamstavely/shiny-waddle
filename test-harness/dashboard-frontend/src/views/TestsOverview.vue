<template>
  <div class="tests-overview-page">
    <Breadcrumb :items="breadcrumbItems" />
    
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Test Management
              <span class="hero-subtitle">Comprehensive Testing Framework</span>
            </h1>
            <p class="hero-description">
              Organize and manage your security tests through a hierarchical structure of tests, 
              suites, harnesses, and batteries. Track results, manage findings, and ensure continuous 
              compliance with automated testing workflows.
            </p>
            <div class="hero-actions">
              <button @click="navigateTo('/tests/suites')" class="btn-primary">View Test Suites</button>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="test-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="testGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="testGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.8 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.6 }" />
                  </linearGradient>
                </defs>
                
                <!-- Test Battery - outer layer -->
                <rect x="20" y="20" width="80" height="50" rx="4" fill="url(#testGradient)" opacity="0.3" stroke="url(#testGradient)" stroke-width="2"/>
                <rect x="25" y="25" width="70" height="40" rx="3" fill="url(#testGradient)" opacity="0.4" stroke="url(#testGradient)" stroke-width="1.5"/>
                
                <!-- Test Harness - middle layer -->
                <rect x="85" y="35" width="80" height="50" rx="4" fill="url(#testGradient)" opacity="0.3" stroke="url(#testGradient)" stroke-width="2"/>
                <rect x="90" y="40" width="70" height="40" rx="3" fill="url(#testGradient)" opacity="0.4" stroke="url(#testGradient)" stroke-width="1.5"/>
                
                <!-- Test Suite - inner layer -->
                <rect x="150" y="50" width="80" height="50" rx="4" fill="url(#testGradient)" opacity="0.3" stroke="url(#testGradient)" stroke-width="2"/>
                <rect x="155" y="55" width="70" height="40" rx="3" fill="url(#testGradient)" opacity="0.4" stroke="url(#testGradient)" stroke-width="1.5"/>
                
                <!-- Test Configuration - bottom -->
                <rect x="85" y="120" width="80" height="50" rx="4" fill="url(#testGradient)" opacity="0.3" stroke="url(#testGradient)" stroke-width="2"/>
                <rect x="90" y="125" width="70" height="40" rx="3" fill="url(#testGradient)" opacity="0.4" stroke="url(#testGradient)" stroke-width="1.5"/>
                
                <!-- Connection lines -->
                <line x1="100" y1="45" x2="125" y2="60" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                <line x1="165" y1="60" x2="125" y2="75" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                <line x1="125" y1="145" x2="125" y2="90" stroke="url(#testGradient)" stroke-width="2" opacity="0.5"/>
                
                <!-- Checkmark symbols -->
                <path d="M 40 40 L 50 50 L 65 30" :style="{ stroke: 'var(--color-secondary)', strokeWidth: '3', fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round', opacity: 0.9 }"/>
                <path d="M 105 55 L 115 65 L 130 45" :style="{ stroke: 'var(--color-secondary)', strokeWidth: '3', fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round', opacity: 0.9 }"/>
                <path d="M 170 70 L 180 80 L 195 60" :style="{ stroke: 'var(--color-secondary)', strokeWidth: '3', fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round', opacity: 0.9 }"/>
                <path d="M 105 140 L 115 150 L 130 130" :style="{ stroke: 'var(--color-secondary)', strokeWidth: '3', fill: 'none', strokeLinecap: 'round', strokeLinejoin: 'round', opacity: 0.9 }"/>
                
                <!-- Accent dots -->
                <circle cx="125" cy="100" r="3" :style="{ fill: 'var(--color-secondary)', opacity: 0.8 }"/>
                <circle cx="60" cy="45" r="2.5" :style="{ fill: 'var(--color-primary)', opacity: 0.7 }"/>
                <circle cx="190" cy="75" r="2.5" :style="{ fill: 'var(--color-primary)', opacity: 0.7 }"/>
                <circle cx="125" cy="145" r="2.5" :style="{ fill: 'var(--color-secondary)', opacity: 0.6 }"/>
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
        Understand the relationship between test configurations, suites, harnesses, and batteries
      </p>
      
      <!-- Relationship Diagram -->
      <div class="diagram-container">
        <svg viewBox="0 0 1000 600" class="hierarchy-diagram">
          <!-- Background -->
          <rect width="1000" height="600" fill="transparent" />
          
          <!-- Level 1: Applications (Infrastructure) -->
          <g class="diagram-level" data-level="applications">
            <rect x="50" y="50" width="180" height="100" rx="8" class="diagram-box config-box" />
            <text x="140" y="95" text-anchor="middle" class="diagram-title">Applications</text>
            <text x="140" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.applications }}</text>
          </g>
          
          <!-- Level 2: Individual Tests -->
          <g class="diagram-level" data-level="tests">
            <rect x="300" y="50" width="180" height="100" rx="8" class="diagram-box test-box" />
            <text x="390" y="95" text-anchor="middle" class="diagram-title">Individual Tests</text>
            <text x="390" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.tests }}</text>
          </g>
          
          <!-- Level 3: Test Suites -->
          <g class="diagram-level" data-level="suites">
            <rect x="550" y="50" width="180" height="100" rx="8" class="diagram-box suite-box" />
            <text x="640" y="95" text-anchor="middle" class="diagram-title">Test Suites</text>
            <text x="640" y="115" text-anchor="middle" class="diagram-subtitle">{{ stats.suites }}</text>
          </g>
          
          <!-- Level 4: Test Harnesses -->
          <g class="diagram-level" data-level="harnesses">
            <rect x="300" y="250" width="180" height="100" rx="8" class="diagram-box harness-box" />
            <text x="390" y="295" text-anchor="middle" class="diagram-title">Test Harnesses</text>
            <text x="390" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.harnesses }}</text>
          </g>
          
          <!-- Level 5: Test Batteries -->
          <g class="diagram-level" data-level="batteries">
            <rect x="550" y="250" width="180" height="100" rx="8" class="diagram-box battery-box" />
            <text x="640" y="295" text-anchor="middle" class="diagram-title">Test Batteries</text>
            <text x="640" y="315" text-anchor="middle" class="diagram-subtitle">{{ stats.batteries }}</text>
          </g>
          
          <!-- Arrows -->
          <!-- Applications → Tests (infrastructure used by tests) -->
          <path d="M 230 100 L 300 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Tests → Suites -->
          <path d="M 480 100 L 550 100" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Suites → Harnesses -->
          <path d="M 640 150 L 390 250" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Harnesses → Batteries -->
          <path d="M 480 300 L 550 300" class="diagram-arrow" marker-end="url(#arrowhead)" />
          
          <!-- Arrow marker definition -->
          <defs>
            <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
              <polygon points="0 0, 10 3, 0 6" class="arrow-fill" />
            </marker>
          </defs>
        </svg>
      </div>
      
      <!-- Relationship Explanation -->
      <div class="relationship-explanation">
        <div class="explanation-steps">
          <div class="step">
            <div class="step-number">1</div>
            <div class="step-content">
              <strong>Application Infrastructure</strong> defines what infrastructure exists (databases, networks, APIs)
            </div>
          </div>
          <div class="step">
            <div class="step-number">2</div>
            <div class="step-content">
              <strong>Individual Tests</strong> validate specific security requirements using infrastructure and policies
            </div>
          </div>
          <div class="step">
            <div class="step-number">3</div>
            <div class="step-content">
              <strong>Test Suites</strong> group related tests together for organized execution
            </div>
          </div>
          <div class="step">
            <div class="step-number">4</div>
            <div class="step-content">
              <strong>Test Harnesses</strong> collect suites and assign them to applications
            </div>
          </div>
          <div class="step">
            <div class="step-number">5</div>
            <div class="step-content">
              <strong>Test Batteries</strong> execute multiple harnesses together with execution configuration
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Stats -->
    <div class="stats-section">
      <h2 class="section-title">Quick Stats</h2>
      <div class="stats-grid">
        <div class="stat-card" @click="navigateTo('/applications')">
          <Settings class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.applications }}</div>
            <div class="stat-label">Applications</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/suites')">
          <List class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.suites }}</div>
            <div class="stat-label">Test Suites</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/harnesses')">
          <Layers class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.harnesses }}</div>
            <div class="stat-label">Test Harnesses</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/batteries')">
          <Battery class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.batteries }}</div>
            <div class="stat-label">Test Batteries</div>
          </div>
        </div>
        <div class="stat-card" @click="navigateTo('/tests/findings')">
          <AlertCircle class="stat-icon" />
          <div class="stat-content">
            <div class="stat-value">{{ stats.findings }}</div>
            <div class="stat-label">Active Findings</div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="actions-section">
      <h2 class="section-title">Quick Actions</h2>
      <div class="actions-grid">
        <button @click="navigateTo('/tests/batteries')" class="action-card">
          <Battery class="action-icon" />
          <span>View Test Batteries</span>
        </button>
        <button @click="navigateTo('/tests/harnesses')" class="action-card">
          <Layers class="action-icon" />
          <span>View Test Harnesses</span>
        </button>
        <button @click="navigateTo('/tests/suites')" class="action-card">
          <List class="action-icon" />
          <span>View Test Suites</span>
        </button>
        <button @click="navigateTo('/tests/findings')" class="action-card">
          <AlertCircle class="action-icon" />
          <span>View Findings</span>
        </button>
        <button @click="navigateTo('/tests/suites/builder')" class="action-card">
          <Plus class="action-icon" />
          <span>Create Test Suite</span>
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { useRouter } from 'vue-router';
import {
  Battery,
  Layers,
  List,
  AlertCircle,
  Settings,
  Plus
} from 'lucide-vue-next';
import Breadcrumb from '../components/Breadcrumb.vue';
import axios from 'axios';

const router = useRouter();

const breadcrumbItems = [
  { label: 'Home', to: '/' },
  { label: 'Tests', to: '/tests' }
];

const stats = ref({
  applications: 0,
  tests: 0,
  suites: 0,
  harnesses: 0,
  batteries: 0,
  findings: 0
});

const loadStats = async () => {
  try {
    const [configsRes, suitesRes, harnessesRes, batteriesRes, resultsRes] = await Promise.all([
      // Test configurations removed - infrastructure is now part of applications
      Promise.resolve({ data: [] }),
      axios.get('/api/v1/test-suites').catch(() => ({ data: [] })),
      axios.get('/api/v1/test-harnesses').catch(() => ({ data: [] })),
      axios.get('/api/v1/test-batteries').catch(() => ({ data: [] })),
      axios.get('/api/test-results?limit=1000').catch(() => ({ data: [] }))
    ]);
    
    // Load applications count for infrastructure stat
    const appsRes = await axios.get('/api/v1/applications').catch(() => ({ data: [] }));
    
    stats.value = {
      applications: appsRes.data?.length || 0,
      tests: 0, // Will be loaded separately if needed
      suites: suitesRes.data?.length || 0,
      harnesses: harnessesRes.data?.length || 0,
      batteries: batteriesRes.data?.length || 0,
      findings: resultsRes.data?.filter((r: any) => !r.passed || r.status === 'failed').length || 0
    };
  } catch (err) {
    console.error('Error loading stats:', err);
  }
};

const navigateTo = (path: string) => {
  router.push(path);
};

onMounted(() => {
  loadStats();
});
</script>

<style scoped>
.tests-overview-page {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

/* Hero Section - matching Homepage style */
.hero-section {
  margin-bottom: 4rem;
}

.hero-card {
  position: relative;
  background: linear-gradient(135deg, rgba(26, 31, 46, 0.8) 0%, rgba(15, 20, 25, 0.9) 100%);
  border: 1px solid rgba(79, 172, 254, 0.3);
  border-radius: 20px;
  padding: 3rem;
  overflow: hidden;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
}

.hero-background {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background-image: 
    radial-gradient(circle at 20% 50%, rgba(79, 172, 254, 0.1) 0%, transparent 50%),
    radial-gradient(circle at 80% 80%, rgba(0, 242, 254, 0.1) 0%, transparent 50%);
  opacity: 0.6;
  pointer-events: none;
}

.hero-content {
  position: relative;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 3rem;
  align-items: center;
  z-index: 1;
}

.hero-text {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.hero-title {
  font-size: 3rem;
  font-weight: 700;
  color: #ffffff;
  margin: 0;
  line-height: 1.2;
}

.hero-subtitle {
  display: block;
  font-size: 1.25rem;
  font-weight: 400;
  color: #4facfe;
  margin-top: 0.5rem;
}

.hero-description {
  font-size: 1.125rem;
  color: #a0aec0;
  line-height: 1.6;
  margin: 0;
}

.hero-actions {
  display: flex;
  gap: 1rem;
  margin-top: 0.5rem;
}

.btn-primary,
.btn-secondary {
  padding: 0.875rem 1.75rem;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s;
  text-decoration: none;
  display: inline-block;
  border: none;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  background: transparent;
  border: 1px solid rgba(79, 172, 254, 0.3);
  color: #4facfe;
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.hero-visual {
  display: flex;
  align-items: center;
  justify-content: center;
}

.svg-container {
  width: 100%;
  max-width: 400px;
  height: auto;
}

.test-svg {
  width: 100%;
  height: auto;
}

/* How It Works Section */
.how-it-works-section {
  margin-bottom: 4rem;
}

.section-title {
  font-size: 2rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 0.75rem;
}

.section-description {
  font-size: 1.125rem;
  color: #a0aec0;
  margin-bottom: 2rem;
}

.diagram-container {
  display: flex;
  justify-content: center;
  margin: 2rem 0;
  padding: 2rem;
  background: rgba(15, 20, 25, 0.5);
  border-radius: 12px;
  border: 1px solid rgba(79, 172, 254, 0.2);
}

.hierarchy-diagram {
  width: 100%;
  max-width: 1000px;
  height: auto;
}

.diagram-box {
  fill: rgba(79, 172, 254, 0.15);
  stroke: rgba(79, 172, 254, 0.5);
  stroke-width: 2;
  transition: all 0.3s;
}

.diagram-box:hover {
  fill: rgba(79, 172, 254, 0.25);
  stroke: rgba(79, 172, 254, 0.8);
}

.config-box {
  fill: rgba(79, 172, 254, 0.15);
}

.test-box {
  fill: rgba(0, 242, 254, 0.15);
}

.suite-box {
  fill: rgba(139, 92, 246, 0.15);
}

.harness-box {
  fill: rgba(236, 72, 153, 0.15);
}

.battery-box {
  fill: rgba(251, 191, 36, 0.15);
}

.diagram-title {
  fill: #ffffff;
  font-size: 14px;
  font-weight: 600;
}

.diagram-subtitle {
  fill: #4facfe;
  font-size: 12px;
  font-weight: 500;
}

.diagram-arrow {
  stroke: rgba(79, 172, 254, 0.6);
  stroke-width: 2;
  fill: none;
}

.arrow-fill {
  fill: rgba(79, 172, 254, 0.6);
}

.relationship-explanation {
  margin-top: 3rem;
  padding-top: 2rem;
  border-top: 1px solid rgba(79, 172, 254, 0.2);
}

.explanation-steps {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1.5rem;
}

.step {
  display: flex;
  gap: 1rem;
  align-items: flex-start;
}

.step-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 600;
  flex-shrink: 0;
}

.step-content {
  flex: 1;
  color: #a0aec0;
  font-size: 0.875rem;
  line-height: 1.5;
}

.step-content strong {
  color: #ffffff;
  display: block;
  margin-bottom: 0.25rem;
}

/* Quick Stats Section */
.stats-section {
  margin-bottom: 4rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1.5rem;
}

.stat-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  align-items: center;
  gap: 1rem;
  cursor: pointer;
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

/* Quick Actions Section */
.actions-section {
  margin-bottom: 3rem;
}

.actions-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
}

.action-card {
  background: rgba(26, 31, 46, 0.6);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 12px;
  padding: 1.5rem;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  cursor: pointer;
  transition: all 0.2s;
  color: #ffffff;
  font-size: 0.875rem;
  font-weight: 500;
}

.action-card:hover {
  background: rgba(26, 31, 46, 0.8);
  border-color: rgba(79, 172, 254, 0.4);
  transform: translateY(-2px);
}

.action-icon {
  width: 32px;
  height: 32px;
  color: #4facfe;
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
