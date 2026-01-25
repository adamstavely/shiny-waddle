import { Injectable, NotFoundException } from '@nestjs/common';
import {
  ComplianceControl,
  ComplianceMapping,
  ComplianceAssessment,
  ComplianceSummary,
  ComplianceGap,
  ComplianceRoadmap,
  ComplianceFramework,
  ControlStatus,
  CreateComplianceMappingDto,
  CreateComplianceAssessmentDto,
} from './entities/compliance.entity';
import { FrameworkLoader } from './frameworks/framework-loader';
import { ViolationsService } from '../violations/violations.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ComplianceService {
  private readonly mappingsFile = path.join(process.cwd(), '..', 'data', 'compliance-mappings.json');
  private readonly assessmentsFile = path.join(process.cwd(), '..', 'data', 'compliance-assessments.json');
  private readonly roadmapsFile = path.join(process.cwd(), '..', 'data', 'compliance-roadmaps.json');
  private mappings: ComplianceMapping[] = [];
  private assessments: ComplianceAssessment[] = [];
  private roadmaps: ComplianceRoadmap[] = [];

  constructor(private readonly violationsService: ViolationsService) {
    this.loadData().catch(err => {
      console.error('Error loading compliance data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      // Load mappings
      try {
        const mappingsData = await fs.readFile(this.mappingsFile, 'utf-8');
        this.mappings = JSON.parse(mappingsData);
      } catch {
        this.mappings = [];
      }

      // Load assessments
      try {
        const assessmentsData = await fs.readFile(this.assessmentsFile, 'utf-8');
        this.assessments = JSON.parse(assessmentsData);
      } catch {
        this.assessments = [];
      }

      // Load roadmaps
      try {
        const roadmapsData = await fs.readFile(this.roadmapsFile, 'utf-8');
        this.roadmaps = JSON.parse(roadmapsData);
      } catch {
        this.roadmaps = [];
      }
    } catch (error) {
      console.error('Error loading compliance data:', error);
    }
  }

  private async saveMappings(): Promise<void> {
    try {
      const dir = path.dirname(this.mappingsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.mappingsFile, JSON.stringify(this.mappings, null, 2));
    } catch (error) {
      console.error('Error saving compliance mappings:', error);
      throw error;
    }
  }

  private async saveAssessments(): Promise<void> {
    try {
      const dir = path.dirname(this.assessmentsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.assessmentsFile, JSON.stringify(this.assessments, null, 2));
    } catch (error) {
      console.error('Error saving compliance assessments:', error);
      throw error;
    }
  }

  private async saveRoadmaps(): Promise<void> {
    try {
      const dir = path.dirname(this.roadmapsFile);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(this.roadmapsFile, JSON.stringify(this.roadmaps, null, 2));
    } catch (error) {
      console.error('Error saving compliance roadmaps:', error);
      throw error;
    }
  }

  // Framework Management
  getAvailableFrameworks(): ComplianceFramework[] {
    return FrameworkLoader.getAvailableFrameworks();
  }

  getFrameworkMetadata(framework: ComplianceFramework) {
    return FrameworkLoader.getFrameworkMetadata(framework);
  }

  getControls(framework: ComplianceFramework): ComplianceControl[] {
    return FrameworkLoader.loadControls(framework);
  }

  getControl(framework: ComplianceFramework, controlId: string): ComplianceControl | null {
    const controls = FrameworkLoader.loadControls(framework);
    return controls.find(c => c.controlId === controlId) || null;
  }

  // Mapping Management
  async createMapping(dto: CreateComplianceMappingDto): Promise<ComplianceMapping> {
    // Verify control exists
    const control = this.getControl(dto.framework, dto.controlId);
    if (!control) {
      throw new NotFoundException(`Control ${dto.controlId} not found in framework ${dto.framework}`);
    }

    const mapping: ComplianceMapping = {
      id: uuidv4(),
      framework: dto.framework,
      controlId: dto.controlId,
      status: dto.status,
      evidence: [],
      violations: dto.violations || [],
      policies: dto.policies || [],
      tests: dto.tests || [],
      notes: dto.notes,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.mappings.push(mapping);
    await this.saveMappings();

    return mapping;
  }

  async findAllMappings(framework?: ComplianceFramework): Promise<ComplianceMapping[]> {
    if (framework) {
      return this.mappings.filter(m => m.framework === framework);
    }
    return this.mappings;
  }

  async findOneMapping(id: string): Promise<ComplianceMapping> {
    const mapping = this.mappings.find(m => m.id === id);
    if (!mapping) {
      throw new NotFoundException(`Compliance mapping with ID ${id} not found`);
    }
    return mapping;
  }

  async updateMapping(id: string, updates: Partial<ComplianceMapping>): Promise<ComplianceMapping> {
    const mapping = await this.findOneMapping(id);
    
    Object.assign(mapping, updates, {
      updatedAt: new Date(),
    });

    await this.saveMappings();
    return mapping;
  }

  async addEvidence(mappingId: string, evidence: any): Promise<ComplianceMapping> {
    const mapping = await this.findOneMapping(mappingId);
    
    mapping.evidence.push({
      ...evidence,
      id: uuidv4(),
      collectedAt: new Date(),
    });

    mapping.updatedAt = new Date();
    await this.saveMappings();

    return mapping;
  }

  // Assessment Management
  async createAssessment(dto: CreateComplianceAssessmentDto): Promise<ComplianceAssessment> {
    const assessment: ComplianceAssessment = {
      id: uuidv4(),
      framework: dto.framework,
      name: dto.name,
      description: dto.description,
      assessedAt: dto.mappings[0]?.lastAssessed || new Date(),
      assessedBy: dto.mappings[0]?.assessedBy || 'system',
      mappings: dto.mappings.map(m => ({
        ...m,
        id: uuidv4(),
        createdAt: new Date(),
        updatedAt: new Date(),
      })),
      summary: this.calculateSummary(dto.framework, dto.mappings),
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.assessments.push(assessment);
    await this.saveAssessments();

    return assessment;
  }

  async findAllAssessments(framework?: ComplianceFramework): Promise<ComplianceAssessment[]> {
    if (framework) {
      return this.assessments.filter(a => a.framework === framework);
    }
    return this.assessments;
  }

  async findOneAssessment(id: string): Promise<ComplianceAssessment> {
    const assessment = this.assessments.find(a => a.id === id);
    if (!assessment) {
      throw new NotFoundException(`Compliance assessment with ID ${id} not found`);
    }
    return assessment;
  }

  async getCurrentAssessment(framework: ComplianceFramework): Promise<ComplianceAssessment | null> {
    const frameworkAssessments = this.assessments.filter(a => a.framework === framework);
    if (frameworkAssessments.length === 0) return null;
    
    // Return most recent assessment
    return frameworkAssessments.sort((a, b) => 
      new Date(b.assessedAt).getTime() - new Date(a.assessedAt).getTime()
    )[0];
  }

  // Gap Analysis
  async performGapAnalysis(framework: ComplianceFramework): Promise<ComplianceGap[]> {
    const controls = this.getControls(framework);
    const currentMappings = this.mappings.filter(m => m.framework === framework);
    const gaps: ComplianceGap[] = [];

    for (const control of controls) {
      const mapping = currentMappings.find(m => m.controlId === control.controlId);
      
      if (!mapping || mapping.status === ControlStatus.NON_COMPLIANT || mapping.status === ControlStatus.PARTIALLY_COMPLIANT) {
        // Get violations affecting this control
        const violations = mapping?.violations || [];
        const violationDetails = await Promise.all(
          violations.map(id => this.violationsService.findOne(id).catch(() => null))
        );

        gaps.push({
          controlId: control.controlId,
          controlTitle: control.title,
          status: mapping?.status || ControlStatus.NOT_ASSESSED,
          priority: control.priority,
          violations: violations,
          remediationSteps: this.generateRemediationSteps(control, violationDetails.filter(Boolean)),
          estimatedEffort: this.estimateEffort(control.priority, violations.length),
        });
      }
    }

    return gaps.sort((a, b) => {
      const priorityOrder = { critical: 4, high: 3, moderate: 2, low: 1 };
      return priorityOrder[b.priority] - priorityOrder[a.priority];
    });
  }

  // Roadmap Management
  async createRoadmap(
    framework: ComplianceFramework,
    name: string,
    description?: string,
    targetDate?: Date
  ): Promise<ComplianceRoadmap> {
    const gaps = await this.performGapAnalysis(framework);

    const roadmap: ComplianceRoadmap = {
      id: uuidv4(),
      framework,
      name,
      description,
      gaps,
      targetComplianceDate: targetDate,
      milestones: [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.roadmaps.push(roadmap);
    await this.saveRoadmaps();

    return roadmap;
  }

  async findAllRoadmaps(framework?: ComplianceFramework): Promise<ComplianceRoadmap[]> {
    if (framework) {
      return this.roadmaps.filter(r => r.framework === framework);
    }
    return this.roadmaps;
  }

  async findOneRoadmap(id: string): Promise<ComplianceRoadmap> {
    const roadmap = this.roadmaps.find(r => r.id === id);
    if (!roadmap) {
      throw new NotFoundException(`Compliance roadmap with ID ${id} not found`);
    }
    return roadmap;
  }

  async updateRoadmap(id: string, updates: Partial<ComplianceRoadmap>): Promise<ComplianceRoadmap> {
    const roadmap = await this.findOneRoadmap(id);
    
    Object.assign(roadmap, updates, {
      updatedAt: new Date(),
    });

    await this.saveRoadmaps();
    return roadmap;
  }

  // Helper Methods
  private calculateSummary(framework: ComplianceFramework, mappings: any[]): ComplianceSummary {
    const controls = this.getControls(framework);
    const totalControls = controls.length;
    
    const compliant = mappings.filter(m => m.status === ControlStatus.COMPLIANT).length;
    const nonCompliant = mappings.filter(m => m.status === ControlStatus.NON_COMPLIANT).length;
    const partiallyCompliant = mappings.filter(m => m.status === ControlStatus.PARTIALLY_COMPLIANT).length;
    const notApplicable = mappings.filter(m => m.status === ControlStatus.NOT_APPLICABLE).length;
    const notAssessed = totalControls - mappings.length;

    const compliancePercentage = totalControls > 0
      ? ((compliant + partiallyCompliant * 0.5) / totalControls) * 100
      : 0;

    // Identify critical gaps
    const criticalGaps: string[] = [];
    const highPriorityGaps: string[] = [];

    for (const mapping of mappings) {
      if (mapping.status === ControlStatus.NON_COMPLIANT) {
        const control = controls.find(c => c.controlId === mapping.controlId);
        if (control) {
          if (control.priority === 'critical') {
            criticalGaps.push(mapping.controlId);
          } else if (control.priority === 'high') {
            highPriorityGaps.push(mapping.controlId);
          }
        }
      }
    }

    return {
      totalControls,
      compliant,
      nonCompliant,
      partiallyCompliant,
      notApplicable,
      notAssessed,
      compliancePercentage,
      criticalGaps,
      highPriorityGaps,
    };
  }

  private generateRemediationSteps(control: ComplianceControl, violations: any[]): string[] {
    const steps: string[] = [];

    if (violations.length > 0) {
      steps.push(`Resolve ${violations.length} related violation(s)`);
    }

    if (control.implementationGuidance) {
      steps.push(control.implementationGuidance);
    }

    steps.push(`Review and update ${control.controlId} implementation`);
    steps.push(`Document evidence of compliance for ${control.controlId}`);
    steps.push(`Re-assess ${control.controlId} compliance status`);

    return steps;
  }

  private estimateEffort(priority: string, violationCount: number): 'low' | 'medium' | 'high' {
    if (priority === 'critical' || violationCount > 5) {
      return 'high';
    }
    if (priority === 'high' || violationCount > 2) {
      return 'medium';
    }
    return 'low';
  }
}

