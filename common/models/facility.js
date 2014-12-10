/**
 * Facility model.
 *
 * @class Facility
 * @inherits {PersistedModel}
 */

module.exports = function(Facility) {
    Facility.disableRemoteMethod('create', true);
    Facility.disableRemoteMethod('upsert', true);
    Facility.disableRemoteMethod('exists', true);
    Facility.disableRemoteMethod('findById', true);
    Facility.disableRemoteMethod('find', true);
    Facility.disableRemoteMethod('findOne', true);
    Facility.disableRemoteMethod('destroyAll', true);
    Facility.disableRemoteMethod('updateAll', true);
    Facility.disableRemoteMethod('deleteById', true);
    Facility.disableRemoteMethod('count', true);
    Facility.disableRemoteMethod('updateAttributes', false);
    Facility.disableRemoteMethod('diff', true);
    Facility.disableRemoteMethod('changes', true);
    Facility.disableRemoteMethod('checkpoint', true);
    Facility.disableRemoteMethod('currentCheckpoint', true);
    Facility.disableRemoteMethod('createUpdates', true);
    Facility.disableRemoteMethod('bulkUpdate', true);
    Facility.disableRemoteMethod('rectifyAllChanges', true);
    Facility.disableRemoteMethod('rectifyChange', true);

    Facility.disableRemoteMethod('login', true);
    Facility.disableRemoteMethod('logout', true);
    Facility.disableRemoteMethod('confirm', true);
    Facility.disableRemoteMethod('resetPassword', true);

    Facility.disableRemoteMethod('__get__accessTokens', false);
    Facility.disableRemoteMethod('__create__accessTokens', false);
    Facility.disableRemoteMethod('__delete__accessTokens', false);
    Facility.disableRemoteMethod('__count__accessTokens', false);

    Facility.disableRemoteMethod('__findById__accessTokens', false);
    Facility.disableRemoteMethod('__destroyById__accessTokens', false);
    Facility.disableRemoteMethod('__updateById__accessTokens', false);
    Facility.disableRemoteMethod('__exists__accessTokens', false);

    require('../../server/methods/facilities')(Facility);
};
