/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Где Jest будет искать ваши тестовые файлы:
  testMatch: [
    '**/src/__tests__/**/*.test.ts',
    '**/src/__tests__/**/*.spec.ts',
    '**/?(*.)+(test|spec).[tj]s?(x)'
  ],

  // Обработка файлов .ts/.tsx через ts-jest с опцией isolatedModules
  transform: {
    '^.+\\.[tj]sx?$': ['ts-jest', { isolatedModules: true }],
  },

  // Поддерживаемые расширения модулей
  moduleFileExtensions: [
    'ts',
    'tsx',
    'js',
    'jsx',
    'json',
    'node'
  ],

  // Сбор покрытия и папка для выходных данных
  collectCoverage: true,
  coverageDirectory: 'coverage',
};
