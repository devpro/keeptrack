module.exports = function (config) {
  config.set({
    basePath: '',
    frameworks: ['jasmine', '@angular-devkit/build-angular'],
    plugins: [
      require('karma-jasmine'),
      require('karma-coverage'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-junit-reporter')
    ],
    client: {
      jasmine: {},
      clearContext: false // leave Jasmine Spec Runner output visible in browser
    },
    preprocessors: {
      'src/**/*.js': ['coverage']
    },
    coverageReporter: {
      dir: require('path').join(__dirname, '/coverage'),
      reporters: [
        { type: 'html', subdir: 'html' },
        { type: 'lcovonly', subdir: '.', file: 'lcov.info' }
      ]
    },
    junitReporter: {
      outputDir: require('path').join(__dirname, '.'),
    },
    reporters: ['progress', 'kjhtml', 'junit', 'coverage'],
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: true,
    browsers: ['Chrome'], // 'Chrome', 'ChromeHeadless'
    singleRun: false
  });
};
