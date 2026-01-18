<template>
  <div class="how-it-works">
    <!-- Hero Section -->
    <div class="hero-section">
      <div class="hero-card">
        <!-- Background texture/grain effect -->
        <div class="hero-background"></div>
        
        <div class="hero-content">
          <div class="hero-text">
            <h1 class="hero-title">
              How It Works
              <span class="hero-subtitle">Understanding the Platform</span>
            </h1>
            <p class="hero-description">
              Heimdall provides a comprehensive security posture management solution that 
              continuously monitors, tests, and validates your application security. 
              Learn how our platform integrates with your infrastructure to deliver 
              real-time security insights and automated compliance validation.
            </p>
            <div class="hero-actions">
              <router-link to="/insights" class="btn-primary">View Dashboard</router-link>
              <router-link to="/tests" class="btn-secondary">Get Started</router-link>
            </div>
          </div>
          <div class="hero-visual">
            <div class="svg-container">
              <svg viewBox="0 0 400 300" class="workflow-svg" preserveAspectRatio="xMidYMid meet">
                <defs>
                  <linearGradient id="workflowGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 1 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 1 }" />
                  </linearGradient>
                  <linearGradient id="workflowGradientDark" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" :style="{ stopColor: 'var(--color-primary)', stopOpacity: 0.6 }" />
                    <stop offset="100%" :style="{ stopColor: 'var(--color-secondary)', stopOpacity: 0.4 }" />
                  </linearGradient>
                  <marker id="arrowhead" markerWidth="10" markerHeight="10" refX="9" refY="3" orient="auto">
                    <polygon points="0 0, 10 3, 0 6" :style="{ fill: 'var(--color-primary)' }" />
                  </marker>
                </defs>
                
                <!-- Step 1: Integration -->
                <g class="workflow-step" transform="translate(50, 50)">
                  <circle cx="50" cy="50" r="40" fill="url(#workflowGradient)" opacity="0.2" stroke="url(#workflowGradient)" stroke-width="2"/>
                  <circle cx="50" cy="50" r="30" fill="url(#workflowGradient)" opacity="0.3"/>
                  <circle cx="50" cy="50" r="20" fill="url(#workflowGradient)" opacity="0.5"/>
                  <text x="50" y="55" text-anchor="middle" fill="#ffffff" font-size="24" font-weight="bold">1</text>
                  <text x="50" y="110" text-anchor="middle" fill="#4facfe" font-size="14" font-weight="600">Integration</text>
                </g>
                
                <!-- Arrow 1 -->
                <line x1="130" y1="100" x2="170" y2="100" stroke="url(#workflowGradient)" stroke-width="3" marker-end="url(#arrowhead)" opacity="0.7"/>
                
                <!-- Step 2: Testing -->
                <g class="workflow-step" transform="translate(200, 50)">
                  <circle cx="50" cy="50" r="40" fill="url(#workflowGradient)" opacity="0.2" stroke="url(#workflowGradient)" stroke-width="2"/>
                  <circle cx="50" cy="50" r="30" fill="url(#workflowGradient)" opacity="0.3"/>
                  <circle cx="50" cy="50" r="20" fill="url(#workflowGradient)" opacity="0.5"/>
                  <text x="50" y="55" text-anchor="middle" fill="#ffffff" font-size="24" font-weight="bold">2</text>
                  <text x="50" y="110" text-anchor="middle" fill="#4facfe" font-size="14" font-weight="600">Testing</text>
                </g>
                
                <!-- Arrow 2 -->
                <line x1="280" y1="100" x2="320" y2="100" stroke="url(#workflowGradient)" stroke-width="3" marker-end="url(#arrowhead)" opacity="0.7"/>
                
                <!-- Step 3: Analysis -->
                <g class="workflow-step" transform="translate(350, 50)">
                  <circle cx="50" cy="50" r="40" fill="url(#workflowGradient)" opacity="0.2" stroke="url(#workflowGradient)" stroke-width="2"/>
                  <circle cx="50" cy="50" r="30" fill="url(#workflowGradient)" opacity="0.3"/>
                  <circle cx="50" cy="50" r="20" fill="url(#workflowGradient)" opacity="0.5"/>
                  <text x="50" y="55" text-anchor="middle" fill="#ffffff" font-size="24" font-weight="bold">3</text>
                  <text x="50" y="110" text-anchor="middle" fill="#4facfe" font-size="14" font-weight="600">Analysis</text>
                </g>
                
                <!-- Down Arrow -->
                <line x1="200" y1="150" x2="200" y2="180" stroke="url(#workflowGradient)" stroke-width="3" marker-end="url(#arrowhead)" opacity="0.7"/>
                
                <!-- Step 4: Reporting -->
                <g class="workflow-step" transform="translate(200, 200)">
                  <rect x="10" y="10" width="80" height="60" rx="8" fill="url(#workflowGradient)" opacity="0.2" stroke="url(#workflowGradient)" stroke-width="2"/>
                  <rect x="20" y="20" width="60" height="40" rx="6" fill="url(#workflowGradient)" opacity="0.4"/>
                  <text x="50" y="50" text-anchor="middle" fill="#ffffff" font-size="20" font-weight="bold">4</text>
                  <text x="50" y="85" text-anchor="middle" fill="#4facfe" font-size="14" font-weight="600">Reporting</text>
                </g>
                
                <!-- Connecting lines -->
                <line x1="100" y1="100" x2="150" y2="200" stroke="url(#workflowGradientDark)" stroke-width="1.5" opacity="0.3" stroke-dasharray="5,5"/>
                <line x1="300" y1="100" x2="250" y2="200" stroke="url(#workflowGradientDark)" stroke-width="1.5" opacity="0.3" stroke-dasharray="5,5"/>
                
                <!-- Accent elements -->
                <circle cx="100" cy="150" r="3" fill="#00f2fe" opacity="0.8"/>
                <circle cx="300" cy="150" r="3" fill="#00f2fe" opacity="0.8"/>
                <circle cx="150" cy="180" r="2.5" fill="#4facfe" opacity="0.7"/>
                <circle cx="250" cy="180" r="2.5" fill="#4facfe" opacity="0.7"/>
              </svg>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Process Steps Section -->
    <div class="process-section">
      <h2 class="section-title">The Process</h2>
      <div class="steps-grid">
        <div class="step-card">
          <div class="step-number">1</div>
          <h3 class="step-title">Integration</h3>
          <p class="step-description">
            Connect Heimdall to your applications, APIs, and infrastructure. 
            Our platform integrates seamlessly with CI/CD pipelines, cloud providers, 
            and existing security tools.
          </p>
        </div>
        
        <div class="step-card">
          <div class="step-number">2</div>
          <h3 class="step-title">Automated Testing</h3>
          <p class="step-description">
            Run comprehensive security tests against your access controls, 
            API endpoints, and data protection mechanisms. Tests execute 
            continuously and on-demand.
          </p>
        </div>
        
        <div class="step-card">
          <div class="step-number">3</div>
          <h3 class="step-title">Real-time Analysis</h3>
          <p class="step-description">
            Get instant insights into your security posture. Our analytics 
            engine processes test results, identifies vulnerabilities, and 
            calculates risk scores in real-time.
          </p>
        </div>
        
        <div class="step-card">
          <div class="step-number">4</div>
          <h3 class="step-title">Compliance Reporting</h3>
          <p class="step-description">
            Generate detailed reports for audits and governance. Track compliance 
            metrics, view violation trends, and export documentation for 
            regulatory requirements.
          </p>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
</script>

<style scoped>
.how-it-works {
  width: 100%;
  min-height: calc(100vh - 60px);
  background: transparent;
  padding: 0;
}

.hero-section {
  max-width: 1400px;
  margin: 48px auto 80px;
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
  width: 500px;
  height: 400px;
  min-width: 500px;
  position: relative;
}

.workflow-svg {
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

.process-section {
  max-width: 1400px;
  margin: 0 auto 80px;
}

.section-title {
  font-size: 2.5rem;
  font-weight: 700;
  color: #ffffff;
  margin-bottom: 48px;
  text-align: left;
}

.steps-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 32px;
}

.step-card {
  background: linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%);
  border: 1px solid rgba(79, 172, 254, 0.2);
  border-radius: 16px;
  padding: 32px;
  transition: all 0.3s;
  position: relative;
}

.step-card:hover {
  transform: translateY(-4px);
  border-color: rgba(79, 172, 254, 0.4);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.3);
}

.step-number {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
  color: #0f1419;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1.5rem;
  font-weight: 700;
  margin-bottom: 20px;
}

.step-title {
  font-size: 1.5rem;
  font-weight: 600;
  color: #ffffff;
  margin-bottom: 12px;
}

.step-description {
  font-size: 1rem;
  color: #a0aec0;
  line-height: 1.6;
}
</style>

