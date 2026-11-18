import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist"] },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  reactHooks.configs.flat.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: globals.browser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
  {
    files: ["eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
