// @ts-check

import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
    eslint.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    {
        languageOptions: {
            parserOptions: {
                projectService: true,
                tsconfigDirName: import.meta.dirname,
            },
        },
        rules: {
            'no-undef': 'off',
            '@typescript-eslint/no-unused-vars': 'off',
            'no-empty': 'off',
            '@typescript-eslint/restrict-template-expressions': 'off',
            '@typescript-eslint/only-throw-error': 'off',
            '@typescript-eslint/no-unnecessary-condition': 'off',
            '@typescript-eslint/unbound-method': 'warn',
            '@typescript-eslint/no-confusing-void-expression': 'off',
            '@typescript-eslint/no-extraneous-class': 'off',
            'no-async-promise-executor': 'off',
            '@typescript-eslint/no-misused-promises': 'off',
            '@typescript-eslint/no-unnecessary-type-parameters': 'off',
            '@typescript-eslint/no-duplicate-enum-values': 'off',
            'prefer-spread': 'off',
            '@typescript-eslint/no-empty-object-type': 'off',
            '@typescript-eslint/no-unsafe-call': 'error',
            '@typescript-eslint/no-unsafe-assignment': 'error',
            'prefer-rest-params': 'error',
            '@typescript-eslint/restrict-plus-operands': 'error',
            '@typescript-eslint/no-unsafe-member-access': 'error',
            '@typescript-eslint/no-unsafe-return': 'error',
            '@typescript-eslint/no-require-imports': 'error',
            '@typescript-eslint/no-explicit-any': 'error',
            '@typescript-eslint/no-unsafe-argument': 'error',
            '@typescript-eslint/no-unnecessary-type-assertion': 'error',
            '@typescript-eslint/no-non-null-assertion': 'error',
            '@typescript-eslint/no-invalid-void-type': 'error',
            '@typescript-eslint/no-unnecessary-boolean-literal-compare': 'error',
            '@typescript-eslint/no-unnecessary-template-expression': 'error',
            'no-case-declarations': 'error',
            '@typescript-eslint/ban-ts-comment': 'error',
            '@typescript-eslint/no-deprecated': 'error',
        },
    },
    {
        files: ['**/*.js'],
        ...tseslint.configs.disableTypeChecked,
    },
);
