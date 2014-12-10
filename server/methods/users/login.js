/**
 * Module dependencies.
 */
var async = require('async');
var _ = require('underscore');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var BasicStrategy = require('passport-http').BasicStrategy;
var BearerStrategy = require('passport-http-bearer').Strategy;
var uid2 = require('uid2');
var moment = require('moment-timezone');

var debug = require('debug')('login');

var errorHandler = require('../../middleware/errorHandler');
var ServerError = require('../../errors/forbidden');
var BadRequestError = require('../../errors/badrequest');
var ForbiddenError = require('../../errors/forbidden');
var AuthorizationError = require('../../errors/authorization');

/**
 * Login a user by with the given `credentials`.
 *
 * @class Login
 */

module.exports = function(server, oauth2) {
    function clientInfo(client) {
        if (!client) {
            return client;
        }
        return client.id + ',' + client.name;
    }

    function doLogin(email, password, next) {
        server.models.User.login({
            email: email,
            password: password
        }, function(err, token) {
            next(err, token);
        });
    }

    /**
     * Passport LocalStrategy
     *
     * This strategy is used to authenticate users based on a username and 
     * password. Anytime a request is made to authorize an application, we must
     * ensure that a user is logged in before asking them to approve the request
     */

    passport.use(new LocalStrategy({
        usernameField: 'email'
    }, function (email, password, next) {
        doLogin(email, password, next);
    }));

    /**
     * Passport BasicStrategy & ClientPasswordStrategy
     *
     * These strategies are used to authenticate registered OAuth clients.
     * They are employed to protect the `token` endpoint, which consumers use to
     * obtain access tokens.  The OAuth 2.0 specification suggests that clients
     * use the HTTP Basic scheme to authenticate.  Use of the client password
     * strategy allows clients to send the same credentials in the request body
     * (as opposed to the `Authorization` header).  While this approach is not
     * recommended by the specification, in practice it is quite common.
     */
    passport.use(new BasicStrategy(
        function (email, password, next) {
           doLogin(email, password, next); 
        }
    ));

    /**
     * BearerStrategy
     *
     * This strategy is used to authenticate either users or clients based on an
     * access token (aka a bearer token).  If a user, they must have previously
     * authorized a client application, which is issued an access token to make
     * requests on behalf of the authorizing user.
     */
    oauth2.useBearerStrategy();
    
    /**
     * Login endpoint
     */
    server.post('/login', function(req, res, next) {
        async.waterfall([
            function(done) {
                // Authenticate client
                passport.authenticate('bearer', {
                    session: false
                }, function(err, client, info) {
                    if (err || !client) {
                        return done(
                            new AuthorizationError(
                                'Unauthorized client', 
                                'unauthorized_client'
                            )
                        );
                    }

                    req.authClient = client;
                    req.authInfo   = info;
                    
                    done(null, client, info.scope || []);
                })(req, res, next);
            }, 
            function(client, scopes, done) {
                // Authenticate user
                passport.authenticate(['basic', 'local'], {
                    session: false
                }, function(err, token) {
                    if (err || !token) {
                        return done(err);
                    }

                    done(null, client, scopes, token);
                })(req, res, next);
            }, 
            function(client, scopes, token, done) {
                server.models.User.findById(token.userId, function(err, user) {
                    if (err || !user) {
                        return done(err);
                    }

                    // if (user.activated == 0) {
                    //     return done(
                    //         new ForbiddenError(
                    //             'Activation proccess not yet performed'
                    //         )
                    //     );
                    // }
                    
                    req.user = user;

                    done(null, client, scopes, user, token.id);
                });
            }, 
            function(client, scopes, user, resToken, done) {
                // Create new session
                server.models.OAuthSession.create({
                    clientId: client.id,
                    ownerType: 'user',
                    ownerId: user.id,
                    userToken: resToken
                }, function(err, session) {
                    if (err) {
                        debug('OAuthSession.create: %j', err);
                        return done(new ServerError('Server Error'));
                    }

                    return done(null, client, scopes, user, session);
                });
            }, 
            function(client, scopes, user, session, done) {
                var tokenExpires = moment().add(oauth2.getTTL(), 'seconds');
                var accessToken = oauth2.generateToken({
                    grant: 'Resource Owner Password Credentials',
                    client: client,
                    user: user,
                    scope: scopes.join(',')
                });

                // Save session access token
                server.models.OAuthSessionAccessToken.create({
                    sessionId: session.id,
                    id: accessToken,
                    timeToLife: oauth2.getTTL(),
                    expiredAt: tokenExpires.toDate()
                }, function(err, accessToken) {
                    if (err) {
                        server.models.OAuthSession.destroyById(session.id);

                        debug(
                            'OAuthSessionAccessToken.create: %j', 
                            err
                        );
                        return done(new ServerError('Server Error'));
                    }

                    done(
                        null, 
                        client, 
                        scopes, 
                        user, 
                        session, 
                        tokenExpires, 
                        accessToken
                    );
                });
            }, 
            function(
                client, 
                scopes, 
                user, 
                session, 
                tokenExpires, 
                accessToken, 
                done
            ) {
                // Save session scopes
                if (scopes.length > 0) {
                    server.models.OAuthScope.find({
                        where: {
                            scope: {
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
                                new BadRequestError(
                                    'Some scope is not available'
                                )
                            );
                        }

                        _.each(scopes, function(item) {
                            server.models.OAuthSessionTokenScope.create({
                                accessToken: accessToken.id,
                                scopeId: item.id
                            });
                        });

                        done(
                            null, 
                            client, 
                            scopes, 
                            user, 
                            session, 
                            tokenExpires, 
                            accessToken
                        );
                    });
                } else {
                    done(
                        null, 
                        client, 
                        scopes, 
                        user, 
                        session, 
                        tokenExpires, 
                        accessToken
                    );
                }
            }, 
            function(
                client, 
                scopes, 
                user, 
                session, 
                tokenExpires, 
                accessToken, 
                done
            ) {
                // Create client refresh token
                var refreshTokenExpires = moment()
                    .add(oauth2.getTTL('tokenRefresh'), 'seconds');
                var refreshToken = oauth2.generateToken({
                    grant: 'Refresh Token',
                    client: client,
                    user: user,
                    scope: scopes.join(',')
                });

                server.models.OAuthSessionRefreshToken.create({
                    id: refreshToken,
                    accessToken: accessToken.id,
                    timeToLife: oauth2.getTTL('tokenRefresh'),
                    expiredAt: refreshTokenExpires.toDate(),
                    clientId: client.id
                }, function(err, refreshToken) {
                    if (err) {
                        server.models.OAuthSession.destroyById(session.id);
                        server.models.OAuthSessionTokenScope.destroyAll({
                            where: {accessToken: accessToken.id}
                        });

                        debug(
                            'OAuthSessionRefreshToken.create: %j', 
                            err
                        );
                        return done(new ServerError('Server Error'));
                    }

                    // Remove current client session
                    server.models.OAuthSession.destroyById(
                        client.token.sessionId
                    );
                    server.models.OAuthSessionTokenScope.destroyAll({
                        where: {sessionAccessTokenId: client.token.id}
                    });

                    // Replace previous client token
                    req.authClient.token = accessToken;

                    done(
                        null, 
                        user, 
                        tokenExpires, 
                        refreshTokenExpires, 
                        accessToken, 
                        refreshToken
                    );
                });
            }
        ], function(
            err, 
            user, 
            tokenExpires, 
            refreshTokenExpires, 
            accessToken, 
            refreshToken
        ) {
            if (err) {
                return next(err);
            }

            var tok = {
                access_token: accessToken.id,
                token_type: 'bearer',
                expires: tokenExpires.format('X'),
                expires_in: oauth2.getTTL(),
                refresh_token: refreshToken.id,
                refresh_expires: refreshTokenExpires.format('X'),
                refresh_expires_in: oauth2.getTTL('tokenRefresh')
            };

            var json = JSON.stringify(tok);
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('Pragma', 'no-cache');
            res.end(json);
        });
    }, errorHandler());
};
