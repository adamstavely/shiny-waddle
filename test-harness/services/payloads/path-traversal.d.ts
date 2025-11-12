export interface PathTraversalPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    os?: 'linux' | 'windows' | 'unix';
    encoding?: 'none' | 'url' | 'double-url' | 'unicode';
}
export declare const PATH_TRAVERSAL_PAYLOADS: PathTraversalPayload[];
export declare function getPathTraversalPayloads(os?: string): PathTraversalPayload[];
export declare function getPathTraversalPayloadsByEncoding(encoding?: string): PathTraversalPayload[];
