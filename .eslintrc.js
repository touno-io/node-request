module.exports = {
  root: true,
  env: { browser: true, node: true },
  parserOptions: {
    parser: 'babel-eslint'
  },
  extends: 'standard',
  // required to lint *.vue files
  plugins: [
    'mocha',
    'node'
  ],
  // add your custom rules here
  rules: {
    'mocha/no-exclusive-tests': 'error',
    strict: 0
  },
  globals: {}
}
