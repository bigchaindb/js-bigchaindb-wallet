/* eslint-disable @typescript-eslint/no-var-requires */
const base = require('../../jest.config.base.js');
const pkg = require('./package.json');

const projectName = 'key-derivation';

module.exports = {
  ...base,
  name: pkg.name,
  displayName: pkg.name,
  rootDir: '../..',
  testMatch: [`<rootDir>/packages/${projectName}/**/*.spec.ts`, `<rootDir>/packages/${projectName}/**/*.e2e-spec.ts`],
  //   "reporters": ["default", "jest-junit"],
  //   "testResultsProcessor": "jest-junit",
  coverageDirectory: `<rootDir>/packages/${projectName}/coverage/`,
  coverageReporters: ['json'],
  //   "coverageReporters": ["lcov", "json"],
  coverageThreshold: {
    global: {
      statements: 55,
      branches: 35,
      functions: 55,
      lines: 50,
    },
  },
  moduleDirectories: ['node_modules'],
  // modulePaths: [`<rootDir>/packages/${projectName}/src/`],
};
