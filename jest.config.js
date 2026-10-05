export default {
  roots: ['<rootDir>'],
  testEnvironment: 'node',
  extensionsToTreatAsEsm: ['.ts'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/test/tsconfig.json', useESM: true, diagnostics: false }]
  },
  restoreMocks: true,
  clearMocks: true,
  testMatch: ['**/test/spec/**/*.ts'],
  reporters: ['default', 'jest-junit'],
  modulePathIgnorePatterns: ['<rootDir>/dist/'],
  moduleNameMapper: {
    '^src/(.*)$': '<rootDir>/src/$1',
    // ts rewrites relative \'.ts\' imports to \'.js\'; resolve them back to the source
    '^(\\.{1,2}/.*)\\.js$': '$1'
  }
};
