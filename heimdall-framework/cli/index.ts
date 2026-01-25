#!/usr/bin/env node

/**
 * Heimdall CLI
 * Main entry point for the Heimdall command-line interface
 */

import { Command } from 'commander';
import { templateCommand } from './commands/template';
import { testCommand } from './commands/test';
import { batchCommand } from './commands/batch';

const program = new Command();

program
  .name('heimdall')
  .description('Heimdall - Data Access Testing Framework for compliance verification')
  .version('1.0.0');

// Register commands
program.addCommand(templateCommand());
program.addCommand(testCommand());
program.addCommand(batchCommand());

// Parse command line arguments
program.parse(process.argv);
