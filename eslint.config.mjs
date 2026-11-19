import globals from 'globals';
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';

//
//  The same rules as ENiGMA½'s own eslint.config.mjs, minus what this repo
//  does not have (JSON linting, the docs site). Formatting is Prettier's job;
//  eslint-config-prettier goes last and switches off the overlapping rules.
//
//  This file is .mjs on purpose: ENiGMA½ loads every *.js at the top of a
//  mod's directory, so the only .js there is av_scanners.js.
//
export default [
    {
        ignores: ['node_modules/**'],
    },

    {
        linterOptions: {
            reportUnusedDisableDirectives: 'off',
        },
    },

    {
        files: ['**/*.js', '**/*.mjs'],
        languageOptions: {
            globals: {
                ...globals.node,
            },
            ecmaVersion: 'latest',
            sourceType: 'commonjs',
        },

        rules: {
            ...js.configs.recommended.rules,

            indent: [
                'error',
                4,
                {
                    SwitchCase: 1,
                },
            ],

            'linebreak-style': ['error', 'unix'],
            quotes: ['error', 'single'],
            semi: ['error', 'always'],
            'comma-dangle': 0,
            'no-trailing-spaces': 'error',
            'no-control-regex': 0,

            'no-unused-vars': [
                'error',
                {
                    args: 'after-used',
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_',
                    caughtErrors: 'none',
                },
            ],
        },
    },

    {
        files: ['**/*.mjs'],
        languageOptions: {
            sourceType: 'module',
        },
    },

    {
        files: ['test/**/*.js'],
        languageOptions: {
            globals: {
                ...globals.mocha,
            },
        },
    },

    prettier,
];
