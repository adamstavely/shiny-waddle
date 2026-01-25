export class CreateFromTemplateDto {
  templateName: string;
  applicationName: string;
  config: {
    // RBAC
    roles?: string[];
    resources?: string[];
    actions?: string[];
    // ABAC
    departments?: string[];
    clearanceLevels?: string[];
    dataClassifications?: string[];
    projects?: string[];
    // HIPAA
    coveredEntities?: string[];
    businessAssociates?: string[];
    // GDPR
    dataControllers?: string[];
    dataProcessors?: string[];
    euMemberStates?: string[];
    // Application context
    applicationId?: string;
  };
  outputFileName?: string;
}
