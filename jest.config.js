// eslint-disable-next-line @typescript-eslint/no-var-requires
const base = require('./jest.config.base.js');

module.exports = {
  ...base,
  projects: ['<rootDir>/packages/*/jest.config.js'],
  // collectCoverageFrom: ['<rootDir>/packages/*/src/**'],
  coverageThreshold: {
    global: {
      statements: 55,
      branches: 35,
      functions: 60,
      lines: 50,
    },
  },
  coverageDirectory: '<rootDir>/coverage/',
  moduleDirectories: ['node_modules'],
};
