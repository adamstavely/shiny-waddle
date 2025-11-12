"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AttackPathAnalyzer = void 0;
class AttackPathAnalyzer {
    constructor(config) {
        this.config = {
            enabled: true,
            maxPathDepth: 5,
            includeTransitivePaths: true,
            prioritizeByExploitability: true,
            prioritizeByAssetCriticality: true,
            framework: 'mitre-attack',
            ...config,
        };
        this.mitreTechniques = new Map();
        this.cweToMitreMapping = new Map();
        this.attackChains = new Map();
        this.initializeAttackFramework();
    }
    async analyze(findings) {
        if (!this.config.enabled || findings.length === 0) {
            return {
                findings,
                paths: [],
                criticalPaths: [],
                attackSurfaces: new Map(),
                statistics: {
                    totalPaths: 0,
                    criticalPathsCount: 0,
                    averagePathLength: 0,
                    mostCommonTechnique: '',
                    highestRiskPath: '',
                },
                prioritization: new Map(),
            };
        }
        const steps = this.mapFindingsToAttackSteps(findings);
        const paths = this.buildAttackPaths(steps, findings);
        const criticalPaths = this.identifyCriticalPaths(paths);
        const attackSurfaces = this.buildAttackSurfaces(findings, steps, paths, criticalPaths);
        const prioritization = this.prioritizeFindings(findings, paths, criticalPaths);
        const statistics = this.calculateStatistics(paths, criticalPaths);
        return {
            findings,
            paths,
            criticalPaths,
            attackSurfaces,
            statistics,
            prioritization,
        };
    }
    mapFindingsToAttackSteps(findings) {
        return findings.map(finding => {
            const cwe = finding.vulnerability?.classification;
            const cve = finding.vulnerability?.cve?.id || finding.vulnerability?.id;
            const techniques = cwe ? this.mapCWEToMitreTechniques(cwe) : [];
            const primaryTechnique = techniques.length > 0 ? techniques[0] : undefined;
            const exploitability = this.assessExploitability(finding);
            const impact = this.assessImpact(finding, cwe);
            const prerequisites = this.findPrerequisites(finding, findings);
            return {
                findingId: finding.id,
                vulnerability: {
                    cve,
                    cwe,
                    title: finding.title,
                    severity: finding.severity,
                },
                asset: {
                    type: finding.asset.type,
                    component: finding.asset.component,
                    applicationId: finding.asset.applicationId,
                },
                technique: primaryTechnique ? {
                    id: primaryTechnique.id,
                    name: primaryTechnique.name,
                    framework: 'mitre-attack',
                } : undefined,
                exploitability,
                prerequisites,
                impact,
            };
        });
    }
    mapCWEToMitreTechniques(cwe) {
        const techniqueIds = this.cweToMitreMapping.get(cwe) || [];
        return techniqueIds
            .map(id => this.mitreTechniques.get(id))
            .filter((t) => t !== undefined);
    }
    assessExploitability(finding) {
        if (finding.severity === 'critical' || finding.severity === 'high') {
            const cvssScore = finding.vulnerability?.cve?.score?.base || 0;
            if (cvssScore >= 9.0) {
                return 'high';
            }
            if (cvssScore >= 7.0) {
                return 'medium';
            }
            return 'low';
        }
        const desc = finding.description.toLowerCase();
        if (desc.includes('exploit') || desc.includes('poc') || desc.includes('proof of concept')) {
            return 'high';
        }
        const cwe = finding.vulnerability?.classification || '';
        const highExploitabilityCWEs = ['CWE-79', 'CWE-89', 'CWE-434', 'CWE-502'];
        if (highExploitabilityCWEs.some(c => cwe.includes(c))) {
            return 'high';
        }
        return finding.severity === 'medium' ? 'medium' : 'low';
    }
    assessImpact(finding, cwe) {
        const impact = {
            dataAccess: false,
            privilegeEscalation: false,
            lateralMovement: false,
            persistence: false,
        };
        if (!cwe) {
            return impact;
        }
        const dataAccessCWEs = ['CWE-89', 'CWE-90', 'CWE-502', 'CWE-434'];
        if (dataAccessCWEs.some(c => cwe.includes(c))) {
            impact.dataAccess = true;
        }
        const privilegeEscalationCWEs = ['CWE-269', 'CWE-284', 'CWE-732'];
        if (privilegeEscalationCWEs.some(c => cwe.includes(c))) {
            impact.privilegeEscalation = true;
        }
        const lateralMovementCWEs = ['CWE-79', 'CWE-352', 'CWE-434'];
        if (lateralMovementCWEs.some(c => cwe.includes(c))) {
            impact.lateralMovement = true;
        }
        const persistenceCWEs = ['CWE-434', 'CWE-502', 'CWE-306'];
        if (persistenceCWEs.some(c => cwe.includes(c))) {
            impact.persistence = true;
        }
        return impact;
    }
    findPrerequisites(finding, allFindings) {
        const prerequisites = [];
        const cwe = finding.vulnerability?.classification;
        if (!cwe) {
            return prerequisites;
        }
        const prerequisiteMappings = {
            'CWE-352': ['CWE-79', 'CWE-284'],
            'CWE-434': ['CWE-79', 'CWE-20'],
            'CWE-502': ['CWE-434', 'CWE-20'],
        };
        const requiredCWEs = prerequisiteMappings[cwe];
        if (requiredCWEs) {
            const appId = finding.asset.applicationId;
            prerequisites.push(...allFindings
                .filter(f => {
                if (f.id === finding.id || !f.asset.applicationId) {
                    return false;
                }
                if (appId && f.asset.applicationId !== appId) {
                    return false;
                }
                const fCWE = f.vulnerability?.classification;
                return fCWE && requiredCWEs.some(rc => fCWE.includes(rc));
            })
                .map(f => f.id));
        }
        return prerequisites;
    }
    buildAttackPaths(steps, findings) {
        const paths = [];
        const processed = new Set();
        const entryPoints = steps.filter(step => {
            return step.prerequisites.length === 0 || step.exploitability === 'high';
        });
        for (const entryPoint of entryPoints) {
            if (processed.has(entryPoint.findingId)) {
                continue;
            }
            const pathsFromEntry = this.buildPathsFromStep(entryPoint, steps, findings, [entryPoint]);
            paths.push(...pathsFromEntry);
            processed.add(entryPoint.findingId);
        }
        if (this.config.includeTransitivePaths) {
            for (const step of steps) {
                if (processed.has(step.findingId) || step.prerequisites.length === 0) {
                    continue;
                }
                const transitivePaths = this.buildTransitivePaths(step, steps, findings);
                paths.push(...transitivePaths);
            }
        }
        return this.deduplicatePaths(paths);
    }
    buildPathsFromStep(step, allSteps, findings, currentPath, depth = 0) {
        if (depth >= this.config.maxPathDepth) {
            return [];
        }
        const paths = [];
        const nextSteps = allSteps.filter(nextStep => {
            if (currentPath.some(s => s.findingId === nextStep.findingId)) {
                return false;
            }
            return this.canReachStep(step, nextStep, allSteps, findings);
        });
        if (nextSteps.length === 0) {
            const path = this.createAttackPath(currentPath, findings);
            if (path) {
                paths.push(path);
            }
        }
        else {
            for (const nextStep of nextSteps) {
                const extendedPath = [...currentPath, nextStep];
                const subPaths = this.buildPathsFromStep(nextStep, allSteps, findings, extendedPath, depth + 1);
                paths.push(...subPaths);
            }
        }
        return paths;
    }
    canReachStep(from, to, allSteps, findings) {
        if (to.prerequisites.includes(from.findingId)) {
            return true;
        }
        if (from.asset.applicationId && to.asset.applicationId) {
            if (from.asset.applicationId === to.asset.applicationId) {
                if (from.technique && to.technique) {
                    const chain = this.attackChains.get(from.technique.id);
                    if (chain && chain.includes(to.technique.id)) {
                        return true;
                    }
                }
            }
        }
        if (from.impact.lateralMovement && to.asset.applicationId) {
            return true;
        }
        if (from.impact.privilegeEscalation && to.asset.applicationId) {
            return true;
        }
        return false;
    }
    buildTransitivePaths(step, allSteps, findings) {
        const paths = [];
        if (step.prerequisites.length > 0) {
            const prerequisiteSteps = allSteps.filter(s => step.prerequisites.includes(s.findingId));
            for (const prereq of prerequisiteSteps) {
                const path = this.createAttackPath([prereq, step], findings);
                if (path) {
                    paths.push(path);
                }
            }
        }
        return paths;
    }
    createAttackPath(steps, findings) {
        if (steps.length === 0) {
            return null;
        }
        const maxSeverity = steps.reduce((max, step) => {
            const severityOrder = {
                critical: 5,
                high: 4,
                medium: 3,
                low: 2,
            };
            return Math.max(max, severityOrder[step.vulnerability.severity] || 0);
        }, 0);
        const pathSeverity = maxSeverity >= 5 ? 'critical' :
            maxSeverity >= 4 ? 'high' :
                maxSeverity >= 3 ? 'medium' : 'low';
        const maxExploitability = steps.reduce((max, step) => {
            const exploitOrder = { high: 3, medium: 2, low: 1 };
            return Math.max(max, exploitOrder[step.exploitability] || 0);
        }, 0);
        const pathExploitability = maxExploitability >= 3 ? 'high' :
            maxExploitability >= 2 ? 'medium' : 'low';
        const impact = {
            overall: 0,
            dataAccess: steps.some(s => s.impact.dataAccess),
            privilegeEscalation: steps.some(s => s.impact.privilegeEscalation),
            lateralMovement: steps.some(s => s.impact.lateralMovement),
            persistence: steps.some(s => s.impact.persistence),
            businessImpact: 0,
        };
        let impactScore = 0;
        if (impact.dataAccess)
            impactScore += 30;
        if (impact.privilegeEscalation)
            impactScore += 25;
        if (impact.lateralMovement)
            impactScore += 20;
        if (impact.persistence)
            impactScore += 25;
        impact.overall = Math.min(100, impactScore);
        const finding = findings.find(f => f.id === steps[0].findingId);
        impact.businessImpact = finding?.businessImpact || this.estimateBusinessImpact(steps, findings);
        const criticality = this.calculatePathCriticality(pathSeverity, pathExploitability, impact);
        const estimatedTimeToExploit = this.estimateTimeToExploit(steps, pathExploitability);
        const remediationPriority = this.calculateRemediationPriority(criticality, impact, steps.length);
        const description = this.generatePathDescription(steps, findings);
        const evidence = steps.map(step => {
            const finding = findings.find(f => f.id === step.findingId);
            return finding?.description || step.vulnerability.title;
        });
        return {
            id: `path-${steps.map(s => s.findingId).join('-')}`,
            name: this.generatePathName(steps),
            steps,
            severity: pathSeverity,
            exploitability: pathExploitability,
            impact,
            criticality,
            estimatedTimeToExploit,
            remediationPriority,
            description,
            evidence,
            createdAt: new Date(),
        };
    }
    identifyCriticalPaths(paths) {
        return paths
            .filter(path => {
            return (path.criticality >= 70 ||
                (path.exploitability === 'high' && path.impact.overall >= 60) ||
                (path.severity === 'critical' && path.impact.dataAccess));
        })
            .sort((a, b) => b.criticality - a.criticality);
    }
    buildAttackSurfaces(findings, steps, paths, criticalPaths) {
        const surfaces = new Map();
        const byApplication = new Map();
        for (const finding of findings) {
            const appId = finding.asset.applicationId || 'unknown';
            if (!byApplication.has(appId)) {
                byApplication.set(appId, { findings: [], steps: [] });
            }
            byApplication.get(appId).findings.push(finding);
        }
        for (const step of steps) {
            const appId = step.asset.applicationId || 'unknown';
            if (byApplication.has(appId)) {
                byApplication.get(appId).steps.push(step);
            }
        }
        for (const [appId, data] of byApplication.entries()) {
            const appPaths = paths.filter(path => path.steps.some(step => step.asset.applicationId === appId));
            const appCriticalPaths = criticalPaths.filter(path => path.steps.some(step => step.asset.applicationId === appId));
            const entryPoints = data.steps.filter(step => step.prerequisites.length === 0 || step.exploitability === 'high');
            const exploitableCount = data.steps.filter(s => s.exploitability !== 'low').length;
            const riskScore = this.calculateAttackSurfaceRiskScore(data.findings, appPaths, appCriticalPaths);
            const mitreTactics = new Set();
            const owaspCategories = new Set();
            for (const step of data.steps) {
                if (step.technique) {
                    const technique = this.mitreTechniques.get(step.technique.id);
                    if (technique) {
                        mitreTactics.add(technique.tactic);
                    }
                }
            }
            const surface = {
                applicationId: appId !== 'unknown' ? appId : undefined,
                assetType: data.findings[0]?.asset.type || 'application',
                entryPoints,
                paths: appPaths,
                criticalPaths: appCriticalPaths,
                totalVulnerabilities: data.findings.length,
                exploitableVulnerabilities: exploitableCount,
                riskScore,
                coverage: {
                    mitreTactics: Array.from(mitreTactics),
                    owaspCategories: Array.from(owaspCategories),
                },
            };
            surfaces.set(appId, surface);
        }
        return surfaces;
    }
    prioritizeFindings(findings, paths, criticalPaths) {
        const prioritization = new Map();
        for (const finding of findings) {
            let priority = finding.riskScore || 50;
            const inCriticalPath = criticalPaths.some(path => path.steps.some(step => step.findingId === finding.id));
            if (inCriticalPath) {
                priority += 30;
            }
            const inPath = paths.some(path => path.steps.some(step => step.findingId === finding.id));
            if (inPath) {
                priority += 15;
            }
            const isEntryPoint = paths.some(path => path.steps[0]?.findingId === finding.id);
            if (isEntryPoint) {
                priority += 10;
            }
            const enablesOthers = paths.some(path => {
                const stepIndex = path.steps.findIndex(step => step.findingId === finding.id);
                return stepIndex >= 0 && stepIndex < path.steps.length - 1;
            });
            if (enablesOthers) {
                priority += 10;
            }
            if (this.config.prioritizeByExploitability) {
                const step = paths
                    .flatMap(p => p.steps)
                    .find(s => s.findingId === finding.id);
                if (step) {
                    if (step.exploitability === 'high') {
                        priority += 15;
                    }
                    else if (step.exploitability === 'low') {
                        priority -= 10;
                    }
                }
            }
            if (this.config.prioritizeByAssetCriticality && finding.asset.applicationId) {
                priority += 5;
            }
            prioritization.set(finding.id, Math.min(100, Math.max(0, priority)));
        }
        return prioritization;
    }
    calculateStatistics(paths, criticalPaths) {
        const avgPathLength = paths.length > 0
            ? paths.reduce((sum, p) => sum + p.steps.length, 0) / paths.length
            : 0;
        const techniques = paths.flatMap(p => p.steps.map(s => s.technique?.id)).filter(Boolean);
        const techniqueCounts = new Map();
        for (const tech of techniques) {
            techniqueCounts.set(tech, (techniqueCounts.get(tech) || 0) + 1);
        }
        const mostCommonTechnique = Array.from(techniqueCounts.entries())
            .sort((a, b) => b[1] - a[1])[0]?.[0] || '';
        const highestRiskPath = criticalPaths.length > 0
            ? criticalPaths.sort((a, b) => b.criticality - a.criticality)[0].id
            : '';
        return {
            totalPaths: paths.length,
            criticalPathsCount: criticalPaths.length,
            averagePathLength: Math.round(avgPathLength * 10) / 10,
            mostCommonTechnique,
            highestRiskPath,
        };
    }
    calculatePathCriticality(severity, exploitability, impact) {
        const severityScores = {
            critical: 40,
            high: 30,
            medium: 20,
            low: 10,
        };
        const exploitabilityScores = {
            high: 30,
            medium: 20,
            low: 10,
        };
        let score = severityScores[severity] + exploitabilityScores[exploitability];
        score += impact.overall * 0.3;
        return Math.min(100, Math.round(score));
    }
    estimateTimeToExploit(steps, exploitability) {
        const baseTimes = {
            high: 2,
            medium: 8,
            low: 24,
        };
        const baseTime = baseTimes[exploitability] || 8;
        return baseTime * steps.length;
    }
    calculateRemediationPriority(criticality, impact, pathLength) {
        let priority = criticality;
        priority += impact.businessImpact * 0.2;
        if (pathLength <= 2) {
            priority += 10;
        }
        return Math.min(100, Math.round(priority));
    }
    estimateBusinessImpact(steps, findings) {
        const maxBusinessImpact = steps.reduce((max, step) => {
            const finding = findings.find(f => f.id === step.findingId);
            return Math.max(max, finding?.businessImpact || 0);
        }, 0);
        return Math.min(100, maxBusinessImpact + (steps.length * 5));
    }
    generatePathDescription(steps, findings) {
        if (steps.length === 1) {
            return `Single-step attack: ${steps[0].vulnerability.title}`;
        }
        const descriptions = steps.map((step, index) => {
            const finding = findings.find(f => f.id === step.findingId);
            return `Step ${index + 1}: ${step.vulnerability.title}${finding?.asset.component ? ` in ${finding.asset.component}` : ''}`;
        });
        return `Multi-step attack path:\n${descriptions.join('\n')}`;
    }
    generatePathName(steps) {
        if (steps.length === 1) {
            return steps[0].vulnerability.title;
        }
        const techniques = steps
            .map(s => s.technique?.name)
            .filter(Boolean)
            .join(' → ');
        return techniques || `Attack Path (${steps.length} steps)`;
    }
    deduplicatePaths(paths) {
        const unique = new Map();
        for (const path of paths) {
            const key = path.steps.map(s => s.findingId).join('|');
            if (!unique.has(key)) {
                unique.set(key, path);
            }
            else {
                const existing = unique.get(key);
                if (path.criticality > existing.criticality) {
                    unique.set(key, path);
                }
            }
        }
        return Array.from(unique.values());
    }
    calculateAttackSurfaceRiskScore(findings, paths, criticalPaths) {
        let score = 0;
        const avgRiskScore = findings.reduce((sum, f) => sum + (f.riskScore || 0), 0) / findings.length;
        score += avgRiskScore * 0.4;
        score += criticalPaths.length * 10;
        score += paths.length * 2;
        return Math.min(100, Math.round(score));
    }
    initializeAttackFramework() {
        const commonTechniques = [
            { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
            { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
            { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
            { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' },
            { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
            { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
            { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
        ];
        for (const tech of commonTechniques) {
            this.mitreTechniques.set(tech.id, tech);
        }
        this.cweToMitreMapping.set('CWE-79', ['T1190', 'T1059']);
        this.cweToMitreMapping.set('CWE-89', ['T1190', 'T1059']);
        this.cweToMitreMapping.set('CWE-352', ['T1190']);
        this.cweToMitreMapping.set('CWE-434', ['T1190', 'T1059']);
        this.cweToMitreMapping.set('CWE-502', ['T1059']);
        this.cweToMitreMapping.set('CWE-284', ['T1078']);
        this.cweToMitreMapping.set('CWE-269', ['T1078']);
        this.attackChains.set('T1190', ['T1059', 'T1078']);
        this.attackChains.set('T1059', ['T1083', 'T1021']);
    }
}
exports.AttackPathAnalyzer = AttackPathAnalyzer;
//# sourceMappingURL=attack-path-analyzer.js.map