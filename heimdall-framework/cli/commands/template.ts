/**
 * Template Command
 * Handles template-related CLI commands
 */

import { Command } from 'commander';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as readline from 'readline';
import { listTemplates, getTemplate, getTemplateDescription, TemplateName } from '../templates';
import { RBACTemplateConfig } from '../templates/rbac-template';
import { ABACTemplateConfig } from '../templates/abac-template';
import { HIPAATemplateConfig } from '../templates/hipaa-template';
import { GDPRTemplateConfig } from '../templates/gdpr-template';

export function templateCommand(): Command {
  const command = new Command('template')
    .description('Manage policy templates');

  // List templates
  command
    .command('list')
    .description('List available templates')
    .action(() => {
      const templates = listTemplates();
      console.log('\nAvailable templates:');
      templates.forEach(name => {
        const template = getTemplate(name as TemplateName);
        if (template) {
          console.log(`  ${name.padEnd(10)} - ${template.description}`);
        }
      });
      console.log('');
    });

  // Preview template
  command
    .command('preview <template-name>')
    .description('Preview a template')
    .action((templateName: string) => {
      const template = getTemplate(templateName as TemplateName);
      if (!template) {
        console.error(`Template "${templateName}" not found.`);
        console.log('Available templates:', listTemplates().join(', '));
        process.exit(1);
      }

      const description = getTemplateDescription(templateName as TemplateName);
      console.log(description);
    });

  // Create from template
  command
    .command('create <template-name>')
    .description('Create a policy from a template')
    .option('-a, --application-name <name>', 'Application name')
    .option('-o, --output <file>', 'Output file path', 'policy.json')
    .option('--roles <roles>', 'Comma-separated list of roles (for RBAC)')
    .option('--resources <resources>', 'Comma-separated list of resources (for RBAC)')
    .option('--actions <actions>', 'Comma-separated list of actions (for RBAC)')
    .option('--departments <departments>', 'Comma-separated list of departments (for ABAC)')
    .option('--clearance-levels <levels>', 'Comma-separated list of clearance levels (for ABAC)')
    .option('--data-classifications <classifications>', 'Comma-separated list of data classifications (for ABAC)')
    .option('--projects <projects>', 'Comma-separated list of projects (for ABAC)')
    .option('--covered-entities <entities>', 'Comma-separated list of covered entities (for HIPAA)')
    .option('--business-associates <associates>', 'Comma-separated list of business associates (for HIPAA)')
    .option('--data-controllers <controllers>', 'Comma-separated list of data controllers (for GDPR)')
    .option('--data-processors <processors>', 'Comma-separated list of data processors (for GDPR)')
    .option('--eu-member-states <states>', 'Comma-separated list of EU member state codes (for GDPR)')
    .option('-i, --interactive', 'Interactive mode for template configuration')
    .action(async (templateName: string, options: any) => {
      const template = getTemplate(templateName as TemplateName);
      if (!template) {
        console.error(`Template "${templateName}" not found.`);
        console.log('Available templates:', listTemplates().join(', '));
        process.exit(1);
      }

      let config: any = {};

      if (options.interactive) {
        config = await interactiveConfig(templateName as TemplateName);
      } else {
        config = parseConfig(templateName as TemplateName, options);
      }

      // Generate policies from template
      const policies = template.create(config);

      // Save to file
      const outputPath = path.resolve(options.output);
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(
        outputPath,
        JSON.stringify({ policies }, null, 2)
      );

      console.log(`\n✅ Created ${policies.length} policies from template "${templateName}"`);
      console.log(`   Saved to: ${outputPath}\n`);
    });

  return command;
}

function parseConfig(templateName: TemplateName, options: any): any {
  const config: any = {
    applicationName: options.applicationName || 'default-app',
  };

  switch (templateName) {
    case 'rbac':
      return {
        ...config,
        roles: options.roles ? options.roles.split(',') : ['admin', 'user', 'viewer'],
        resources: options.resources ? options.resources.split(',') : ['dataset', 'report'],
        actions: options.actions ? options.actions.split(',') : ['read', 'write'],
      } as RBACTemplateConfig;

    case 'abac':
      return {
        ...config,
        departments: options.departments ? options.departments.split(',') : undefined,
        clearanceLevels: options.clearanceLevels ? options.clearanceLevels.split(',') : undefined,
        dataClassifications: options.dataClassifications ? options.dataClassifications.split(',') : undefined,
        projects: options.projects ? options.projects.split(',') : undefined,
      } as ABACTemplateConfig;

    case 'hipaa':
      return {
        ...config,
        coveredEntities: options.coveredEntities ? options.coveredEntities.split(',') : undefined,
        businessAssociates: options.businessAssociates ? options.businessAssociates.split(',') : undefined,
      } as HIPAATemplateConfig;

    case 'gdpr':
      return {
        ...config,
        dataControllers: options.dataControllers ? options.dataControllers.split(',') : undefined,
        dataProcessors: options.dataProcessors ? options.dataProcessors.split(',') : undefined,
        euMemberStates: options.euMemberStates ? options.euMemberStates.split(',') : undefined,
      } as GDPRTemplateConfig;

    default:
      return config;
  }
}

async function interactiveConfig(templateName: TemplateName): Promise<any> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const question = (query: string): Promise<string> => {
    return new Promise(resolve => rl.question(query, resolve));
  };

  const config: any = {};

  console.log(`\nConfiguring ${templateName.toUpperCase()} template...\n`);

  config.applicationName = await question('Application name: ') || 'default-app';

  switch (templateName) {
    case 'rbac':
      const roles = await question('Roles (comma-separated, default: admin,user,viewer): ');
      config.roles = roles ? roles.split(',').map((r: string) => r.trim()) : ['admin', 'user', 'viewer'];

      const resources = await question('Resources (comma-separated, default: dataset,report): ');
      config.resources = resources ? resources.split(',').map((r: string) => r.trim()) : ['dataset', 'report'];

      const actions = await question('Actions (comma-separated, default: read,write): ');
      config.actions = actions ? actions.split(',').map((a: string) => a.trim()) : ['read', 'write'];
      break;

    case 'abac':
      const departments = await question('Departments (comma-separated, optional): ');
      if (departments) config.departments = departments.split(',').map((d: string) => d.trim());

      const clearanceLevels = await question('Clearance levels (comma-separated, optional): ');
      if (clearanceLevels) config.clearanceLevels = clearanceLevels.split(',').map((c: string) => c.trim());

      const dataClassifications = await question('Data classifications (comma-separated, optional): ');
      if (dataClassifications) config.dataClassifications = dataClassifications.split(',').map((d: string) => d.trim());

      const projects = await question('Projects (comma-separated, optional): ');
      if (projects) config.projects = projects.split(',').map((p: string) => p.trim());
      break;

    case 'hipaa':
      const coveredEntities = await question('Covered entities (comma-separated, optional): ');
      if (coveredEntities) config.coveredEntities = coveredEntities.split(',').map((e: string) => e.trim());

      const businessAssociates = await question('Business associates (comma-separated, optional): ');
      if (businessAssociates) config.businessAssociates = businessAssociates.split(',').map((b: string) => b.trim());
      break;

    case 'gdpr':
      const dataControllers = await question('Data controllers (comma-separated, optional): ');
      if (dataControllers) config.dataControllers = dataControllers.split(',').map((c: string) => c.trim());

      const dataProcessors = await question('Data processors (comma-separated, optional): ');
      if (dataProcessors) config.dataProcessors = dataProcessors.split(',').map((p: string) => p.trim());

      const euMemberStates = await question('EU member states (comma-separated, optional): ');
      if (euMemberStates) config.euMemberStates = euMemberStates.split(',').map((s: string) => s.trim());
      break;
  }

  rl.close();
  return config;
}
