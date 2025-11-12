module.exports = {
  moduleFileExtensions: ['js', 'json', 'ts'],
  rootDir: 'src',
  testRegex: '.*\\.spec\\.ts$',
  transform: {
    '^.+\\.(t|j)s$': 'ts-jest',
  },
  collectCoverageFrom: [
    '**/*.(t|j)s',
  ],
  coverageDirectory: '../coverage',
  testEnvironment: 'node',
  moduleNameMapper: {
    '^../../core/(.*)$': '<rootDir>/../core/$1',
    '^../../services/(.*)$': '<rootDir>/../services/$1',
  },
  globals: {
    'ts-jest': {
      tsconfig: {
        paths: {
          '../../core/*': ['../core/*'],
          '../../services/*': ['../services/*'],
        },
      },
    },
  },
};

