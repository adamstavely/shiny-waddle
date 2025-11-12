import { UnifiedFinding, ECSDocument } from '../core/unified-finding-schema';
export declare class ECSAdapter {
    toECS(finding: UnifiedFinding): ECSDocument;
    fromECS(doc: ECSDocument): UnifiedFinding;
    private mapSeverityToECS;
    private mapECSSeverity;
    private generateTags;
    batchToECS(findings: UnifiedFinding[]): ECSDocument[];
    batchFromECS(docs: ECSDocument[]): UnifiedFinding[];
}
