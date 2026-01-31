import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

export interface LLMConfig {
  provider: 'openai' | 'anthropic' | 'azure' | 'local' | 'disabled';
  apiKey?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  baseUrl?: string;
}

export interface LLMPrompt {
  system: string;
  user: string;
  context?: Record<string, any>;
}

export interface PolicyRecommendation {
  id: string;
  type: 'add-rule' | 'modify-condition' | 'add-tag' | 'optimize' | 'security-improvement';
  title: string;
  description: string;
  reasoning: string;
  impact: 'low' | 'medium' | 'high';
  effort: 'low' | 'medium' | 'high';
  suggestedChange: Record<string, any>;
  confidence: number; // 0-100
}

export interface QueryResponse {
  answer: string;
  confidence: number;
  sources: string[];
  suggestedActions?: string[];
}

@Injectable()
export class LLMIntegrationService {
  private readonly logger = new Logger(LLMIntegrationService.name);
  private config: LLMConfig;

  constructor(private readonly configService: ConfigService) {
    this.config = this.loadConfig();
  }

  /**
   * Load LLM configuration from environment variables
   */
  private loadConfig(): LLMConfig {
    const provider = (this.configService.get<string>('LLM_PROVIDER') || 'disabled') as LLMConfig['provider'];
    
    return {
      provider,
      apiKey: this.configService.get<string>('LLM_API_KEY'),
      model: this.configService.get<string>('LLM_MODEL') || this.getDefaultModel(provider),
      temperature: parseFloat(this.configService.get<string>('LLM_TEMPERATURE') || '0.7'),
      maxTokens: parseInt(this.configService.get<string>('LLM_MAX_TOKENS') || '2000'),
      baseUrl: this.configService.get<string>('LLM_BASE_URL'),
    };
  }

  private getDefaultModel(provider: LLMConfig['provider']): string {
    switch (provider) {
      case 'openai':
        return 'gpt-4-turbo-preview';
      case 'anthropic':
        return 'claude-3-opus-20240229';
      case 'azure':
        return 'gpt-4';
      default:
        return 'gpt-3.5-turbo';
    }
  }

  /**
   * Check if LLM is enabled and configured
   */
  isEnabled(): boolean {
    return this.config.provider !== 'disabled' && !!this.config.apiKey;
  }

  /**
   * Generate enhanced executive summary using LLM
   */
  async generateEnhancedSummary(
    data: {
      policies: any[];
      compliance: any;
      gaps: any[];
    },
    options?: { language?: string; tone?: 'executive' | 'technical' }
  ): Promise<string> {
    if (!this.isEnabled()) {
      this.logger.warn('LLM not enabled, returning template-based summary');
      return this.generateTemplateSummary(data);
    }

    try {
      const prompt: LLMPrompt = {
        system: `You are an expert security policy analyst. Generate clear, concise executive summaries of policy changes and compliance status. Use ${options?.tone || 'executive'} language suitable for ${options?.tone === 'executive' ? 'C-level executives' : 'technical teams'}.`,
        user: `Generate an executive summary for the following policy changes:

Policies Changed: ${data.policies.length}
Compliance Score: ${data.compliance.compliancePercentage}%
Total Gaps: ${data.gaps.length}
Critical Gaps: ${data.gaps.filter((g: any) => g.severity === 'critical').length}

Key Policy Changes:
${data.policies.slice(0, 10).map((p: any) => `- ${p.name}: ${p.description || 'No description'}`).join('\n')}

Compliance Gaps:
${data.gaps.slice(0, 10).map((g: any) => `- ${g.title}: ${g.description}`).join('\n')}

Generate a comprehensive executive summary that highlights:
1. Overall policy change trends
2. Compliance status and key concerns
3. Critical actions needed
4. Business impact

Keep it concise (2-3 paragraphs) and actionable.`,
        context: {
          dateRange: { start: new Date().toISOString(), end: new Date().toISOString() },
          options,
        },
      };

      return await this.callLLM(prompt);
    } catch (error) {
      this.logger.error('Error generating enhanced summary:', error);
      return this.generateTemplateSummary(data);
    }
  }

  /**
   * Generate policy recommendations
   */
  async generatePolicyRecommendations(
    policy: any,
    context: {
      similarPolicies?: any[];
      complianceIssues?: any[];
      bestPractices?: string[];
    }
  ): Promise<PolicyRecommendation[]> {
    if (!this.isEnabled()) {
      return this.generateTemplateRecommendations(policy, context);
    }

    try {
      const prompt: LLMPrompt = {
        system: 'You are an expert security policy advisor. Analyze policies and provide actionable recommendations for improvement.',
        user: `Analyze this policy and provide recommendations:

Policy: ${policy.name}
Type: ${policy.type}
Description: ${policy.description || 'No description'}
Rules: ${policy.rules?.length || 0}
Status: ${policy.status}

${context.complianceIssues?.length ? `Compliance Issues:\n${context.complianceIssues.map((i: any) => `- ${i.title}: ${i.description}`).join('\n')}` : ''}

Provide 3-5 specific recommendations with:
- Type (add-rule, modify-condition, add-tag, optimize, security-improvement)
- Title
- Description
- Reasoning
- Impact (low/medium/high)
- Effort (low/medium/high)
- Confidence (0-100)

Return as JSON array.`,
      };

      const response = await this.callLLM(prompt);
      return this.parseRecommendations(response);
    } catch (error) {
      this.logger.error('Error generating recommendations:', error);
      return this.generateTemplateRecommendations(policy, context);
    }
  }

  /**
   * Answer natural language queries about policies
   */
  async answerQuery(
    query: string,
    context: {
      policies?: any[];
      compliance?: any;
    }
  ): Promise<QueryResponse> {
    if (!this.isEnabled()) {
      return this.generateTemplateQueryResponse(query, context);
    }

    try {
      const prompt: LLMPrompt = {
        system: 'You are a helpful assistant that answers questions about security policies and compliance. Provide accurate, concise answers based on the provided context.',
        user: `Answer this question about policies: "${query}"

Context:
- Total Policies: ${context.policies?.length || 0}
- Compliance Score: ${context.compliance?.compliancePercentage || 0}%

${context.policies?.slice(0, 5).map((p: any) => `- ${p.name}: ${p.description || 'No description'}`).join('\n') || 'No policies available'}

Provide a clear, accurate answer. If you don't have enough information, say so.`,
      };

      const answer = await this.callLLM(prompt);
      return {
        answer,
        confidence: 85, // Would calculate based on response quality
        sources: context.policies?.slice(0, 3).map((p: any) => p.id) || [],
        suggestedActions: [],
      };
    } catch (error) {
      this.logger.error('Error answering query:', error);
      return this.generateTemplateQueryResponse(query, context);
    }
  }

  /**
   * Call LLM API based on provider
   */
  private async callLLM(prompt: LLMPrompt): Promise<string> {
    switch (this.config.provider) {
      case 'openai':
        return this.callOpenAI(prompt);
      case 'anthropic':
        return this.callAnthropic(prompt);
      case 'azure':
        return this.callAzureOpenAI(prompt);
      case 'local':
        return this.callLocalModel(prompt);
      default:
        throw new Error(`Unsupported LLM provider: ${this.config.provider}`);
    }
  }

  /**
   * Call OpenAI API
   */
  private async callOpenAI(prompt: LLMPrompt): Promise<string> {
    try {
      const response = await axios.post(
        'https://api.openai.com/v1/chat/completions',
        {
          model: this.config.model,
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: prompt.user },
          ],
          temperature: this.config.temperature,
          max_tokens: this.config.maxTokens,
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.config.apiKey}`,
          },
        }
      );

      return response.data.choices[0]?.message?.content || '';
    } catch (error: any) {
      this.logger.error('OpenAI API error:', error.response?.data || error.message);
      throw new Error(`OpenAI API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * Call Anthropic API
   */
  private async callAnthropic(prompt: LLMPrompt): Promise<string> {
    try {
      const response = await axios.post(
        'https://api.anthropic.com/v1/messages',
        {
          model: this.config.model,
          max_tokens: this.config.maxTokens,
          messages: [
            { role: 'user', content: `${prompt.system}\n\n${prompt.user}` },
          ],
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.config.apiKey!,
            'anthropic-version': '2023-06-01',
          },
        }
      );

      return response.data.content[0]?.text || '';
    } catch (error: any) {
      this.logger.error('Anthropic API error:', error.response?.data || error.message);
      throw new Error(`Anthropic API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * Call Azure OpenAI API
   */
  private async callAzureOpenAI(prompt: LLMPrompt): Promise<string> {
    try {
      const baseUrl = this.config.baseUrl || 'https://your-resource.openai.azure.com';
      
      const response = await axios.post(
        `${baseUrl}/openai/deployments/${this.config.model}/chat/completions?api-version=2024-02-15-preview`,
        {
          messages: [
            { role: 'system', content: prompt.system },
            { role: 'user', content: prompt.user },
          ],
          temperature: this.config.temperature,
          max_tokens: this.config.maxTokens,
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'api-key': this.config.apiKey!,
          },
        }
      );

      return response.data.choices[0]?.message?.content || '';
    } catch (error: any) {
      this.logger.error('Azure OpenAI API error:', error.response?.data || error.message);
      throw new Error(`Azure OpenAI API error: ${error.response?.data?.error?.message || error.message}`);
    }
  }

  /**
   * Call local model (placeholder for future implementation)
   */
  private async callLocalModel(prompt: LLMPrompt): Promise<string> {
    // Placeholder for local model integration (e.g., Ollama, local LLM server)
    this.logger.warn('Local model integration not yet implemented');
    return this.generateTemplateSummary({ policies: [], compliance: { compliancePercentage: 0 }, gaps: [] });
  }

  /**
   * Parse recommendations from LLM response
   */
  private parseRecommendations(response: string): PolicyRecommendation[] {
    try {
      // Try to parse as JSON
      const jsonMatch = response.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return parsed.map((rec: any, index: number) => ({
          id: `rec-${Date.now()}-${index}`,
          type: rec.type || 'optimize',
          title: rec.title || 'Recommendation',
          description: rec.description || '',
          reasoning: rec.reasoning || '',
          impact: rec.impact || 'medium',
          effort: rec.effort || 'medium',
          suggestedChange: rec.suggestedChange || {},
          confidence: rec.confidence || 70,
        }));
      }
    } catch (error) {
      this.logger.warn('Failed to parse recommendations as JSON:', error);
    }

    // Fallback: generate template recommendations
    return [];
  }

  /**
   * Generate template-based summary (fallback)
   */
  private generateTemplateSummary(data: {
    policies: any[];
    compliance: any;
    gaps: any[];
  }): string {
    return `
Policy Changes Summary (${data.policies.length} policies):

${data.policies.length} policies were modified in this period.
Overall compliance score: ${data.compliance.compliancePercentage}%
${data.gaps.length} compliance gaps detected.

Key areas of focus:
- ${data.gaps.filter((g: any) => g.severity === 'critical').length} critical gaps require immediate attention
- ${data.gaps.filter((g: any) => g.severity === 'high').length} high-priority gaps should be addressed within 48 hours
    `.trim();
  }

  /**
   * Generate template recommendations (fallback)
   */
  private generateTemplateRecommendations(
    policy: any,
    context: { complianceIssues?: any[] }
  ): PolicyRecommendation[] {
    const recommendations: PolicyRecommendation[] = [];

    if (!policy.rules || policy.rules.length === 0) {
      recommendations.push({
        id: 'rec-template-1',
        type: 'add-rule',
        title: 'Add Policy Rules',
        description: 'This policy has no rules defined. Consider adding rules to enforce access control.',
        reasoning: 'Policies without rules cannot enforce access control effectively.',
        impact: 'high',
        effort: 'medium',
        suggestedChange: { rules: [] },
        confidence: 90,
      });
    }

    if (policy.status === 'draft') {
      recommendations.push({
        id: 'rec-template-2',
        type: 'optimize',
        title: 'Review and Activate Policy',
        description: 'This policy is in draft status. Review and activate it to start enforcement.',
        reasoning: 'Draft policies are not enforced.',
        impact: 'medium',
        effort: 'low',
        suggestedChange: { status: 'active' },
        confidence: 85,
      });
    }

    return recommendations;
  }

  /**
   * Generate template query response (fallback)
   */
  private generateTemplateQueryResponse(
    query: string,
    context: { policies?: any[]; compliance?: any }
  ): QueryResponse {
    return {
      answer: `Based on the available data, there are ${context.policies?.length || 0} policies with a compliance score of ${context.compliance?.compliancePercentage || 0}%. For more specific information, please enable LLM integration.`,
      confidence: 50,
      sources: [],
      suggestedActions: [],
    };
  }
}
