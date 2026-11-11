import js from '@eslint/js';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

export default [
  { ignores: ['dist', 'node_modules'] },
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx,mjs}'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', parserOptions: { ecmaFeatures: { jsx: true } }, globals: { ...globals.browser, ...globals.node } },
    plugins: { react, 'react-hooks': reactHooks },
    rules: {
      ...(reactHooks.configs?.flat?.recommended?.rules ?? reactHooks.configs?.recommended?.rules ?? {}),
      'react/jsx-uses-vars': 'error',      // a component used only in JSX counts as used
      'react/jsx-uses-react': 'off',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
  { files: ['test/**/*.{js,jsx}'], languageOptions: { globals: { ...globals.browser, ...globals.node, ...globals.vitest } } },
];
