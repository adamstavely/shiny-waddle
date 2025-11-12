export interface CommandInjectionPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    os?: 'linux' | 'windows' | 'unix';
    technique: 'basic' | 'chaining' | 'encoding' | 'time-based';
}
export declare const COMMAND_INJECTION_PAYLOADS: CommandInjectionPayload[];
export declare function getCommandInjectionPayloads(os?: string): CommandInjectionPayload[];
export declare function getCommandInjectionPayloadsByTechnique(technique: string): CommandInjectionPayload[];
