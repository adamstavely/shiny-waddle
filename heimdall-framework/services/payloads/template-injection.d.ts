export interface TemplateInjectionPayload {
    payload: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    templateEngine: 'jinja2' | 'freemarker' | 'velocity' | 'twig' | 'smarty' | 'handlebars' | 'mustache' | 'erb';
}
export declare const TEMPLATE_INJECTION_PAYLOADS: TemplateInjectionPayload[];
export declare function getTemplateInjectionPayloads(engine?: string): TemplateInjectionPayload[];
