/**
 * Module dependencies.
 */
var sha1 = require('sha1');
var uid2 = require('uid2');
var async = require('async');
var moment = require('moment-timezone');
var _ = require('underscore');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password')
    .Strategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var oauth2Provider = require('loopback-component-oauth2');
var debug = require('debug')('oauth2');

var CONFIG = require('../config');

var ServerError = require('../errors/server');
var BadRequestError = require('../errors/badrequest');
var AuthorizationError = require('../errors/authorization');

/**
 * `OAuth2` constructor.
 *
 * @param {Object} server The server instance
 * 
 * @api public
 */

function OAuth2(server) {
    this._server = server;
    this._models = server.models;

    this._server.use(passport.initialize());
    
    // create OAuth 2.0 server
    this._OAuth2Server = oauth2Provider.createServer();

    // The urlencoded middleware is required for oAuth 2.0 protocol endpoints
    this._server.use(this._server.loopback.urlencoded({extended: false}));
    
    // Strategies for oauth2 client-id/client-secret login
    // HTTP basic
    passport.use('oauth2-client-basic', new BasicStrategy(
        this.clientLogin.bind(this)
    ));
    
    // Body
    passport.use('oauth2-client-password', new ClientPasswordStrategy(
        this.clientLogin.bind(this)
    ));
    
    var version = require('../../package.json').version.split('.').shift();
    this.authenticate(['/v' + (version > 0 ? version : 1)], {
        session: false, 
        scope: 'read,write'
    });
}

OAuth2.prototype.getServer = function() {
    return this._OAuth2Server;
};

OAuth2.prototype.getProvider = function() {
    return this._oauth2;
};

OAuth2.prototype.clientInfo = function(client) {
    if (!client) {
        return client;
    }

    return client.id + ',' + client.name;
};

OAuth2.prototype.userInfo = function (user) {
    if (!user) {
        return user;
    }

    return user.id + ',' + user.username + ',' + user.email;
};

OAuth2.prototype.clientLogin = function(clientId, clientSecret, done) {
    debug('clientLogin: %s', clientId);
    this._models.Application.findById(clientId, function(err, client) {
        if (err) {
            return done(err);
        }

        if (!client) {
            return done(null, false);
        }

        if (client.restApiKey !== clientSecret) {
            return done(null, false);
        }

        return done(null, client);
    });
};

OAuth2.prototype.validateScopes = function(scopes, done) {
    this._models.OAuthScope.find({
        where: {
            id: {
                inq: scopes
            }
        }
    }, function(err, availableScopes) {
        if (err) {
            debug('OAuthScope.find: %j', err);
            return done(new ServerError('Server Error'));
        }

        if (scopes.length !== availableScopes.length) {
            return done(
                new BadRequestError('Some scope is not available')
            );
        }

        done(null);
    });
};

/**
 * BearerStrategy
 *
 * This strategy is used to authenticate users based on an access token
 * (aka a bearer token). The user must have previously authorized a client
 * application, which is issued an access token to make requests on behalf
 * of the authorizing user.
 */
OAuth2.prototype.useBearerStrategy = function(fn) {
    fn = fn || this.bearerStrategyCallback.bind(this);
    passport.use(new BearerStrategy({passReqToCallback: true}, fn));
};

OAuth2.prototype.bearerStrategyCallback = function(req, accessToken, callback) {
    var self = this;

    async.waterfall([
        function(done) {
            self._models.OAuthSessionAccessToken.findById(
                accessToken, 
                function(err, token) {
                    if (err) {
                        debug(
                            'OAuthSessionAccessTokens.findById: %j', 
                            err
                        );
                        return done(new ServerError('Server Error'));
                    }

                    if ( ! _.isObject(token)) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }
                    
                    if (moment().unix() > moment(token.expiredAt).unix()) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }

                    done(null, token);
                }
            );
        }, 
        function(token, done) {
            self._models.OAuthSession.findById(
                token.sessionId, 
                function(err, session) {
                    if (err) {
                        debug('OAuthSession.findById: %j', err);
                        return done(new ServerError('Server Error'));
                    }

                    if ( ! _.isObject(session)) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }

                    done(null, token, session);
                }
            );
        }, 
        function(token, session, done) {
            self._models.Application.findById(
                session.clientId, 
                function(err, client) {
                    if (err) {
                        debug('Application.findOne: %j', err);
                        return done(new ServerError('Server Error'));
                    }

                    if ( ! _.isObject(client)) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }

                    done(null, token, session, client);
                }
            );
        }, 
        function(token, session, client, done) {
            client = client.toObject();
            client.token = token;

            if (session.ownerType === 'user') {
                self._models.User.findById(
                    session.ownerId, 
                    function(err, user) {
                        if (err) {
                            debug('User.findById: %j', err);
                            return done(new ServerError('Server Error'));
                        }

                        if ( ! _.isObject(user)) {
                            return done(
                                new AuthorizationError(
                                    'Unauthorized client', 
                                    'unauthorized_client'
                                )
                            );
                        }

                        done(null, client, user);
                    }
                );
            } else {
                done(null, client, null);
            }
        }, 
        function(client, user, done) {
            self._models.OAuthSessionTokenScope.find({
                where: {
                    sessionAccessTokenId: client.token.id
                }
            }, function(err, sessionTokens) {
                if (err) {
                    debug('OAuthSessionTokenScope.find: %j', err);
                    return done(new ServerError('Server Error'));
                }

                done(null, client, user, sessionTokens);
            });
        }, 
        function(client, user, sessionTokens, done) {
            if (sessionTokens.length > 0) {
                async.map(sessionTokens, function(sessionToken, next) {
                    self._models.OAuthScope.findById(
                        sessionToken.scope, 
                        function(err, scope) {
                            if (err) {
                                debug(
                                    'OAuthScope.findById: %j', 
                                    err
                                );
                                return next(new ServerError('Server Error'));
                            }

                            next(null, scope.id);
                        }
                    );
                }, function(err, results) {
                    if (err) {
                        return done(err);
                    }
                    
                    if (user !== null) {
                        return done(null, user, {
                            client: client, 
                            scope: results
                        });
                    }

                    return done(null, client, {scope: results});
                });
            } else {
                if (user !== null) {
                    return done(null, user, {
                        client: client
                    });
                }

                done(null, client, {});
            }
        }
    ], function(err, owner, info) {
        if (err) {
            return callback(err);
        }

        req.authClient = owner;
        req.authInfo   = info;
        req.authUser   = null;

        if (_.isObject(req.authInfo.client)) {
            req.authClient = req.authInfo.client;
            req.authUser   = owner;

            delete req.authInfo;
        }

        callback(null, owner, info);
    });
};

/*
 * Client credentials flow
 */
OAuth2.prototype.useClientCredentialsFlow = function(fn) {
    fn = fn || this.clientCredentialsFlowCallback.bind(this);
    this._OAuth2Server.exchange(oauth2Provider.exchange.clientCredentials({
        scopeSeparator: ','
    }, fn));
};

OAuth2.prototype.clientCredentialsFlowCallback = function(
    client, 
    scopes, 
    next
) {
    var self = this;

    if (typeof scopes === 'function') {
        next = scopes;
        scopes = [];
    }
    
    async.waterfall([
        function(done) {
            if (scopes.length > 0) {
                self.validateScopes(scopes, done);
            } else {
                done(null);
            }
        }, 
        function(done) {
            // Create a session
            self._models.OAuthSession.create({
                clientId: client.id,
                ownerType: 'client',
                ownerId: client.id
            }, function(err, session) {
                if (err) {
                    debug('OAuthSession.create: %j', err);
                    return done(new ServerError('Server Error'));
                }

                done(null, session);
            });
        }, 
        function(session, done) {
            var token = self.generateToken({
                grant: 'Client Credentials',
                client: client,
                scope: scopes
            });
            debug('Generating access token: %s %s %s',
                token, self.clientInfo(client), scopes);

            var tokenExpires = moment().add(self.getTTL(), 'seconds');
            
            // Create a access token
            self._models.OAuthSessionAccessToken.create({
                sessionId: session.id,
                id: token,
                timeToLife: self.getTTL(),
                expiredAt: tokenExpires.toDate()
            }, function(err, accessToken) {
                if (err) {
                    self._models.OAuthSession.destroyById(session.id);

                    debug(
                        'OAuthSessionAccessToken.create: %j', 
                        err
                    );

                    return done(new ServerError('Server Error'));
                }

                done(null, accessToken, tokenExpires);
            });
        }, 
        function(accessToken, tokenExpires, done) {
            // Save session scopes
            if (scopes.length > 0) {
                _.each(scopes, function(item) {
                    self._models.OAuthSessionTokenScope.create({
                        accessToken: accessToken.id,
                        scope: item
                    });
                });
            }

            return done(null, accessToken.id, {
                expires: tokenExpires.format('X'),
                expires_in: self.getTTL()
            });
        }
    ], function(err, tokenId, param) {
        if (err) {
            return next(err);
        }

        next(null, tokenId, null, param);
    });
};

/*
 * Refresh token flow
 */
OAuth2.prototype.useRefreshTokenFlow = function(fn) {
    fn = fn || this.refreshTokenFlowCallback.bind(this);
    this._OAuth2Server.exchange(oauth2Provider.exchange.refreshToken({
        scopeSeparator: ','
    }, fn));
};

OAuth2.prototype.refreshTokenFlowCallback = function(
    client, 
    token, 
    scopes, 
    next
) {
    var self = this;

    if (typeof scopes === 'function') {
        next = scopes;
        scopes = [];
    }

    async.waterfall([
        function(done) {
            if (scopes.length > 0) {
                self.validateScopes(scopes, done);
            } else {
                done(null);
            }
        }, 
        function(done) {
            self._models.OAuthSessionRefreshToken.findOne({
                where: {
                    id: token, 
                    clientId: client.id
                }
            }, function(err, refreshToken) {
                if (err) {
                    debug('OAuthSessionRefreshToken.findOne: %j', err);
                    return done(new ServerError('Server Error'));
                }

                if ( ! _.isObject(refreshToken)) {
                    return done(
                        new AuthorizationError(
                            'Unauthorized client', 
                            'unauthorized_client'
                        )
                    );
                }

                done(null, refreshToken);
            });
        }, 
        function(refreshToken, done) {
            self._models.OAuthSessionAccessToken.findById(
                refreshToken.accessToken, 
                function(err, accessToken) {
                    if (err) {
                        debug('OAuthSessionAccessToken.findById: %j', err);
                        return done(new ServerError('Server Error'));
                    }

                    if ( ! _.isObject(accessToken)) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }

                    done(null, refreshToken, accessToken);
                }
            );
        }, 
        function(refreshToken, accessToken, done) {
            if (moment() > moment.unix(refreshToken.expiredAt)) {
                self._models.OAuthSessionTokenScope.destroyAll({
                    where: {accessToken: refreshToken.accessToken}
                });

                self._models.OAuthSessionAccessToken.destroyById(
                    refreshToken.accessToken
                );

                self._models.OAuthSessionRefreshToken.destroyById(
                    refreshToken.id
                );

                self._models.OAuthSession.destroyById(accessToken.sessionId);

                return done(
                    new AuthorizationError(
                            'Unauthorized client', 
                            'unauthorized_client'
                    )
                );
            } else {
                var tokenExpires = moment().add(self.getTTL(), 'seconds');
                var token = self.generateToken({
                    grant: 'Refresh Token',
                    client: client,
                    scope: scopes
                });

                // Create a new access token
                self._models.OAuthSessionAccessToken.create({
                    sessionId: accessToken.sessionId,
                    id: token,
                    timeToLife: self.getTTL(),
                    expiredAt: tokenExpires.toDate()
                }, function(err, newAccessToken) {
                    if (err) {
                        debug(
                            'OAuthSessionAccessToken.create: %j', 
                            err
                        );
                        return done(new ServerError('Server Error'));
                    }

                    self._models.OAuthSessionAccessToken.destroyById(
                        accessToken.id
                    );

                    done(null, refreshToken, newAccessToken, tokenExpires);
                });
            }
        }, 
        function(refreshToken, accessToken, tokenExpires, done) {
            refreshToken.updateAttributes({
                accessToken: accessToken.id
            }, function(err, refreshToken) {
                if (err) {
                    debug('refreshToken.updateAttributes: %j', err);
                    return done(new ServerError('Server Error'));
                }

                return done(null, accessToken.id, {
                    expires: tokenExpires.format('X'),
                    expires_in: self.getTTL()
                });
            });
        }
    ], function(err, tokenId, param) {
        if (err) {
            return next(err);
        }

        next(null, tokenId, null, param);
    });
};

/*
 * token endpoint
 * 
 * `token` middleware handles client requests to exchange authorization grants
 * for access tokens.  Based on the grant type being exchanged, the above
 * exchange middleware will be invoked to handle the request.  Clients must
 * authenticate when making requests to this endpoint.
*/
OAuth2.prototype.tokenEndpoint = function(option) {
    return [
        passport.authenticate(
            ['oauth2-client-password', 'oauth2-client-basic'],
            { session: false }
        ), 
        this._OAuth2Server.token(), 
        this._OAuth2Server.errorHandler()
    ];
};

/**
 * Set up oAuth 2.0 authentication for the paths
 * @param {String|String[]} paths One or more paths
 * @param options
 */
OAuth2.prototype.authenticate = function(paths, options) {
    options = options || {};
    if (typeof paths === 'string') {
        paths = [paths];
    }
    var authenticators = [];
    for (var i = 0, n = paths.length; i < n; i++) {
        authenticators = [passport.authenticate('bearer', options)];
        this._server.use(paths[i], authenticators);
    }
};

OAuth2.prototype.getTTL = function(grantType, clientId, resourceOwner, scopes) {
    switch (grantType) {
        case 'code':
            return 300;
        case 'tokenRefresh':
            return CONFIG.refreshTokenTtl;
        default:
            return CONFIG.tokenTtl;
    }
};

OAuth2.prototype.generateToken = function(option) {
    return uid2(5) + sha1(JSON.stringify(option)) + uid2(5);
};

/**
 * Authorization endpoints
 */
OAuth2.prototype.routes = function() {
    this._server.post('/oauth/authorize', this.tokenEndpoint());
};

/**
 * Expose `OAuth2`.
 */
exports = module.exports = OAuth2;