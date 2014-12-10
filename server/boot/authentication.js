/**
 * Module dependencies.
 */
var OAuth2 = require('../oauth2');

/**
 * Authentication middleware
 */
module.exports = function enableAuthentication(server) {
    // enable authentication
    // server.enableAuth();
    
    // Set up OAuth 2
    var oauth2 = new OAuth2(server);

    oauth2.useBearerStrategy();
    oauth2.useClientCredentialsFlow();
    oauth2.useRefreshTokenFlow();

    // Set endpoint paths need to be authenticated
    var version = require('../../package.json').version.split('.').shift();
    oauth2.authenticate(['/v' + (version > 0 ? version : 1)], {
        session: false, 
        scope: 'read,write'
    });
    
    // Setup authorization endpoints
    oauth2.routes();

    // User authentication endpoint
    require('../methods/users/login')(server, oauth2);
};
