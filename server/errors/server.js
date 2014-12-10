var util = require('util');
/**
 * `ServerError` error.
 *
 * @api public
 */
function ServerError(message) {
  Error.call(this);
  Error.captureStackTrace(this, ServerError);
  this.name = 'ServerError';
  this.message = message;
  this.status = 500;
}

/**
 * Inherit from `Error`.
 */
util.inherits(ServerError, Error);

/**
 * Expose `ServerError`.
 */
module.exports = ServerError;
