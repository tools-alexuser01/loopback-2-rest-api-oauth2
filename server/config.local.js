var GLOBAL_CONFIG = require('./config');
var PACKAGE = require('../package.json');

var version = PACKAGE.version.split('.').shift();

var isDevEnv = (process.env.NODE_ENV || 'development') === 'development';

module.exports = {
    restApiRoot: GLOBAL_CONFIG.restApiRoot + '/v' + (version > 0 ? version : 1),
    host: process.env.HOST || '127.0.0.1',
    port: process.env.PORT || 3000,
    livereload: process.env.LIVE_RELOAD,
    isDevEnv: isDevEnv
};