import { ref, computed, type Ref } from 'vue';

export interface ValidationRule {
  validator: (value: any) => boolean;
  message: string;
}

export interface FieldValidation {
  value: Ref<any>;
  rules: ValidationRule[];
  touched: Ref<boolean>;
  error: Ref<string | null>;
  validate: () => boolean;
  reset: () => void;
}

/**
 * Composable for form validation
 * 
 * @param fields - Object mapping field names to validation rules
 * @returns Object containing validation state and methods
 * 
 * @example
 * ```ts
 * const form = ref({
 *   name: '',
 *   email: '',
 * });
 * 
 * const validation = useFormValidation({
 *   name: {
 *     value: computed(() => form.value.name),
 *     rules: [
 *       { validator: (v) => v.length > 0, message: 'Name is required' },
 *       { validator: (v) => v.length >= 3, message: 'Name must be at least 3 characters' },
 *     ],
 *   },
 *   email: {
 *     value: computed(() => form.value.email),
 *     rules: [
 *       { validator: (v) => v.length > 0, message: 'Email is required' },
 *       { validator: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v), message: 'Invalid email format' },
 *     ],
 *   },
 * });
 * 
 * // Validate all fields
 * if (validation.validateAll()) {
 *   // Submit form
 * }
 * 
 * // Validate single field
 * validation.fields.name.validate();
 * ```
 */
export function useFormValidation(fields: Record<string, { value: Ref<any>; rules: ValidationRule[] }>) {
  const fieldValidations: Record<string, FieldValidation> = {};

  // Initialize field validations
  Object.keys(fields).forEach((fieldName) => {
    const field = fields[fieldName];
    const touched = ref(false);
    const error = ref<string | null>(null);

    const validate = (): boolean => {
      touched.value = true;
      error.value = null;

      for (const rule of field.rules) {
        if (!rule.validator(field.value.value)) {
          error.value = rule.message;
          return false;
        }
      }

      return true;
    };

    const reset = () => {
      touched.value = false;
      error.value = null;
    };

    fieldValidations[fieldName] = {
      value: field.value,
      rules: field.rules,
      touched,
      error,
      validate,
      reset,
    };
  });

  const validateAll = (): boolean => {
    let isValid = true;
    Object.values(fieldValidations).forEach((field) => {
      if (!field.validate()) {
        isValid = false;
      }
    });
    return isValid;
  };

  const resetAll = () => {
    Object.values(fieldValidations).forEach((field) => {
      field.reset();
    });
  };

  const isValid = computed(() => {
    return Object.values(fieldValidations).every(
      (field) => !field.error.value
    );
  });

  const hasErrors = computed(() => {
    return Object.values(fieldValidations).some(
      (field) => field.error.value !== null
    );
  });

  return {
    fields: fieldValidations,
    validateAll,
    resetAll,
    isValid,
    hasErrors,
  };
}

/**
 * Common validation rules
 */
export const validationRules = {
  required: (message = 'This field is required'): ValidationRule => ({
    validator: (value: any) => {
      if (value === null || value === undefined) return false;
      if (typeof value === 'string') return value.trim().length > 0;
      if (Array.isArray(value)) return value.length > 0;
      return true;
    },
    message,
  }),

  minLength: (min: number, message?: string): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return false;
      return String(value).length >= min;
    },
    message: message || `Must be at least ${min} characters`,
  }),

  maxLength: (max: number, message?: string): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return String(value).length <= max;
    },
    message: message || `Must be no more than ${max} characters`,
  }),

  email: (message = 'Invalid email format'): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value));
    },
    message,
  }),

  url: (message = 'Invalid URL format'): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      try {
        new URL(String(value));
        return true;
      } catch {
        return false;
      }
    },
    message,
  }),

  number: (message = 'Must be a number'): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return !isNaN(Number(value));
    },
    message,
  }),

  min: (min: number, message?: string): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return Number(value) >= min;
    },
    message: message || `Must be at least ${min}`,
  }),

  max: (max: number, message?: string): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return Number(value) <= max;
    },
    message: message || `Must be no more than ${max}`,
  }),

  pattern: (pattern: RegExp, message: string): ValidationRule => ({
    validator: (value: any) => {
      if (!value) return true;
      return pattern.test(String(value));
    },
    message,
  }),
};
