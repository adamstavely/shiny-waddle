"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validatorRegistry = exports.ValidatorRegistry = void 0;
class ValidatorRegistry {
    constructor() {
        this.validators = new Map();
        this.validatorsByType = new Map();
    }
    register(validator) {
        if (this.validators.has(validator.id)) {
            throw new Error(`Validator with id "${validator.id}" is already registered`);
        }
        this.validators.set(validator.id, validator);
        const testType = validator.testType;
        if (!this.validatorsByType.has(testType)) {
            this.validatorsByType.set(testType, []);
        }
        this.validatorsByType.get(testType).push(validator);
        console.log(`Registered validator: ${validator.name} (${validator.id})`);
    }
    unregister(validatorId) {
        const validator = this.validators.get(validatorId);
        if (!validator) {
            return;
        }
        this.validators.delete(validatorId);
        const testType = validator.testType;
        const validators = this.validatorsByType.get(testType);
        if (validators) {
            const index = validators.indexOf(validator);
            if (index >= 0) {
                validators.splice(index, 1);
            }
        }
    }
    get(validatorId) {
        return this.validators.get(validatorId);
    }
    getByType(testType) {
        return this.validatorsByType.get(testType) || [];
    }
    getAll() {
        return Array.from(this.validators.values());
    }
    findValidatorsForSuite(suite) {
        return this.getAll().filter(validator => validator.canHandle(suite));
    }
    list() {
        return this.getAll().map(v => ({
            id: v.id,
            name: v.name,
            testType: v.testType,
            description: v.description,
        }));
    }
}
exports.ValidatorRegistry = ValidatorRegistry;
exports.validatorRegistry = new ValidatorRegistry();
//# sourceMappingURL=validator-registry.js.map