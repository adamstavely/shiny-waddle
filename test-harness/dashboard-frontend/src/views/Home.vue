<template>
  <div class="home">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              Heimdall
              <span class="hero-subtitle">Data Access Security Posture Management</span>
            </h1>
            <p class="hero-description">
              Comprehensive data access security posture management platform for modern applications. 
              Continuously assess, monitor, and improve your data access security across 
              access controls, API security, data protection, and compliance requirements 
              with automated testing and real-time visibility.
            </p>
            <div class="hero-actions">
              <router-link to="/dashboard" class="btn-primary">View Dashboard</router-link>
              <router-link to="/tests" class="btn-secondary">Run Tests</router-link>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 250 200" class="sentinel-svg" preserveAspectRatio="xMidYMid meet">
                  <defs>
                  <linearGradient id="sentinelGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:1" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:1" />
                  </linearGradient>
                  <linearGradient id="sentinelGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:#4facfe;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:#00f2fe;stop-opacity:0.6" />
                  </linearGradient>
                </defs>
                
                <!-- Shield base - outer layer -->
                <path 
                  d="M 125 20 L 165 40 L 165 80 Q 165 120 125 160 Q 85 120 85 80 L 85 40 Z" 
                  fill="url(#sentinelGradient)" 
                  opacity="0.3"
                  stroke="url(#sentinelGradient)"
                  stroke-width="2"
                />
                
                <!-- Shield middle layer -->
                <path 
                  d="M 125 30 L 155 45 L 155 80 Q 155 110 125 145 Q 95 110 95 80 L 95 45 Z" 
                  fill="url(#sentinelGradient)" 
                  opacity="0.4"
                  stroke="url(#sentinelGradient)"
                  stroke-width="1.5"
                />
                
                <!-- Shield inner layer -->
                <path 
                  d="M 125 40 L 145 50 L 145 80 Q 145 100 125 130 Q 105 100 105 80 L 105 50 Z" 
                  fill="url(#sentinelGradient)" 
                  opacity="0.5"
                />
                
                <!-- Central checkmark/verification symbol -->
                <path 
                  d="M 110 100 L 120 110 L 140 85" 
                  stroke="#00f2fe" 
                  stroke-width="4" 
                  fill="none" 
                  stroke-linecap="round" 
                  stroke-linejoin="round"
                  opacity="0.9"
                />
                
                <!-- Security rings - outer -->
                <circle cx="125" cy="100" r="75" fill="none" stroke="url(#sentinelGradientDark)" stroke-width="1" opacity="0.3"/>
                <circle cx="125" cy="100" r="65" fill="none" stroke="url(#sentinelGradientDark)" stroke-width="1" opacity="0.4"/>
                
                <!-- Accent dots -->
                <circle cx="125" cy="50" r="3" fill="#00f2fe" opacity="0.8"/>
                <circle cx="175" cy="100" r="2.5" fill="#4facfe" opacity="0.7"/>
                <circle cx="75" cy="100" r="2.5" fill="#4facfe" opacity="0.7"/>
                <circle cx="125" cy="150" r="2.5" fill="#00f2fe" opacity="0.6"/>
                
                <!-- Scanning lines effect -->
                <line x1="65" y1="100" x2="85" y2="100" stroke="url(#sentinelGradient)" stroke-width="2" opacity="0.5"/>
                <line x1="165" y1="100" x2="185" y2="100" stroke="url(#sentinelGradient)" stroke-width="2" opacity="0.5"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Features Section -->
    <div class="features-section">
      <h2 class="section-title">Key Features</h2>
      <div class="features-grid">
        <div class="feature-card">
          <div class="feature-icon">
            <ShieldCheck />
          </div>
          <h3 class="feature-title">Access Control Testing</h3>
          <p class="feature-description">
            Comprehensive testing for RBAC and ABAC policies with automated validation.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <BarChart3 />
          </div>
          <h3 class="feature-title">Real-time Monitoring</h3>
          <p class="feature-description">
            Track compliance scores and violations in real-time with detailed analytics.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <FileText />
          </div>
          <h3 class="feature-title">Compliance Reports</h3>
          <p class="feature-description">
            Generate comprehensive reports for audits and governance documentation.
          </p>
        </div>
        
        <div class="feature-card">
          <div class="feature-icon">
            <TestTube />
          </div>
          <h3 class="feature-title">Automated Test Suites</h3>
          <p class="feature-description">
            Create and run test suites to validate data access policies continuously.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ShieldCheck, BarChart3, FileText, TestTube } from 'lucide-vue-next';
</script>

<style scoped>
.home {
  width: 100%;
  height: 100%;
  max-height: 100vh;
  background: transparent;
  padding: 0;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.hero-section {
  max-width: 1400px;
  width: 100%;
  margin: 48px auto 0;
  padding: 0 24px;
  flex-shrink: 0;
  box-sizing: border-box;
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
  display: flex;
  align-items: center;
  gap: 64px;
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
  font-size: 1.25rem;
  color: #a0aec0;
  line-height: 1.6;
  max-width: 600px;
  margin-bottom: 32px;
}

.hero-actions {
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
}

.btn-primary,
.btn-secondary {
  padding: 14px 28px;
  border-radius: 12px;
  font-weight: 600;
  font-size: 1rem;
  text-decoration: none;
  transition: all 0.2s;
  display: inline-block;
}

.btn-primary {
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  border: none;
}

.btn-primary:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(79, 172, 254, 0.4);
}

.btn-secondary {
  background: transparent;
  color: #4facfe;
  border: 2px solid rgba(79, 172, 254, 0.3);
}

.btn-secondary:hover {
  background: rgba(79, 172, 254, 0.1);
  border-color: rgba(79, 172, 254, 0.5);
}

.hero-visual {
  flex-shrink: 0;
  display: none;
}

.svg-container {
  width: 400px;
  height: 320px;
  min-width: 400px;
  position: relative;
}

.sentinel-svg {
  width: 100%;
  height: 100%;
  display: block;
  filter: drop-shadow(0 8px 24px rgba(79, 172, 254, 0.3));
}

@media (min-width: 1024px) {
  .hero-visual {
    display: block;
  }
  
  .hero-title {
    font-size: 5rem;
  }
  
  .hero-subtitle {
    font-size: 2.5rem;
  }
}

.features-section {
  max-width: 1400px;
  width: 100%;
  margin: 48px auto 48px;
  padding: 0 24px;
  flex-shrink: 0;
  box-sizing: border-box;
}

.section-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 48px;
  text-align: left;
}

.features-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px;
}

@media (max-width: 1200px) {
  .features-grid {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .features-grid {
    grid-template-columns: 1fr;
  }
}

.feature-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
  transition: all 0.3s;
}

.feature-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.feature-icon {
  width: 64px;
  height: 64px;
  margin-bottom: 20px;
  color: #4facfe;
}

.feature-icon :deep(svg) {
  width: 100%;
  height: 100%;
}

.feature-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.feature-description {
  font-size: 1rem;
  color: #a0aec0;
  line-height: 1.6;
}
</style>

