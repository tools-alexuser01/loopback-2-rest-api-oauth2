/**
 * Module dependencies.
 */
var _ = require('underscore');
var debug = require('debug')('facility');

var ServerError = require('../../errors/server');
var AuthorizationError = require('../../errors/authorization');

module.exports = function(Facility) {
    Facility.getFacilities = function(userId, next) {
        // This endpoint should only be called by logged in user
        if (userId === 0) {
            return next(
                new AuthorizationError('Access denied', 'access_denied')
            );
        }

        Facility.all(function(err, facilities) {
            if (err) {
                debug('Facility.all: %j', err);
                return next(new ServerError('Server error'));
            }

            next(null, facilities);
        });
    };

    Facility.remoteMethod('getFacilities', {
        description: "get facilities",
        accepts:[
            {arg: 'userId', type: 'string', http: function(ctx) {
                var userId = 0;
                
                if ( ! _.isUndefined(ctx.req.authUser)
                 && ! _.isNull(ctx.req.authUser)) {
                    userId = ctx.req.authUser.id;
                }

                return userId;
            }, description: 'Do not supply this argument, it is automatically' +
            ' extracted from request headers.'}
        ],
        returns: {root: true, type: 'object'},    
        http: {path: '/', verb: 'get'}        
    });
};