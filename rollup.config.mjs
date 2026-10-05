import cleanup from 'rollup-plugin-cleanup';
import typescript from '@rollup/plugin-typescript';
import nodeResolve from '@rollup/plugin-node-resolve';
import { readFileSync } from 'node:fs';

const banner = readFileSync(new URL('./build-scripts/license-template.txt', import.meta.url), 'utf8').trim();

const tsPlugin = (outDir) => typescript({
  tsconfig: './tsconfig.json',
  compilerOptions: {
    sourceMap: true,
    declaration: false,
    emitDeclarationOnly: false,
    outDir,
  }
});

export default [
  // ESM: dependencies stay external
  {
    input: 'src/index.ts',
    external: ['@okta/auth-foundation'],
    output: {
      dir: 'dist/esm',
      format: 'es',
      sourcemap: true,
      preserveModules: true,
      preserveModulesRoot: 'src',
      banner,
    },
    plugins: [tsPlugin('dist/esm'), cleanup({ extensions: ['js', 'ts'], comments: 'none' })]
  },
  // CJS: @okta/auth-foundation is ESM-only, so it is bundled in
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/cjs/index.cjs',
      format: 'cjs',
      exports: 'named',
      sourcemap: true,
      banner,
      // keep v4's `const OktaJwtVerifier = require('@okta/jwt-verifier')` working
      footer: 'module.exports = Object.assign(exports.default, exports);',
    },
    plugins: [nodeResolve({ preferBuiltins: true }), tsPlugin('dist/cjs'), cleanup({ extensions: ['js', 'ts'], comments: 'none' })]
  }
];
