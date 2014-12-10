var loopback = require('loopback');
var boot = require('loopback-boot');
var bodyParser = require('body-parser');

var app = module.exports = loopback();

// Set up the /favicon.ico
app.use(loopback.favicon());

// request pre-processing middleware
app.use(loopback.compress());

// -- Add your pre-processing middleware here --

// Set up body parsers
// parse application/json
app.use(bodyParser.json());
// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));
// parse multipart/form-data
app.use(require('multer')());

// boot scripts mount components like REST API
boot(app, __dirname);

// -- Mount static files here--
// All static middleware should be registered at the end, as all requests
// passing the static middleware are hitting the file system
// Example:
//   var path = require('path');
//   app.use(loopback.static(path.resolve(__dirname, '../client')));

// Requests that get this far won't be handled
// by any middleware. Convert them into a 404 error
// that will be handled later down the chain.
app.use(loopback.urlNotFound());

// The ultimate error handler.
app.use(loopback.errorHandler());

// app.dataSources.db.automigrate([
//     'User', 
//     'Application', 
//     'Role', 
//     'ACL', 
//     'RoleMapping', 
//     'AccessToken', 
//     'OAuthScope', 
//     'OAuthSession', 
//     'OAuthSessionAccessToken', 
//     'OAuthSessionRefreshToken', 
//     'OAuthSessionTokenScope'
// ], function(err) {
//     console.log(err);
// });

// app.models.OAuthScope.create({
//     id: 'read',
//     name: 'Read',
//     description: 'Read access'
// });

// app.models.OAuthScope.create({
//     id: 'write',
//     name: 'Write',
//     description: 'Write access'
// });

// app.models.User.create({
//     username: 'sulaeman',
//     email: 'me@sulaeman.com',
//     password: 'sulaeman'
// }, function(err, user) {
//     if (err) {
//         console.log(err);
//     } else {
//         app.models.Application.create({
//             name: 'Default',
//             owner: user.id,
//             email: 'me@sulaeman.com',
//             emailVerified: true
//         }, function(err, application) {
//             if (err) {
//                 console.log(err);
//             } else {
//                 console.log(application);
//             }
//         });
//     }
// });

app.start = function() {
    // start the web server
    return app.listen(function() {
        app.emit('started');
        console.log('Web server listening at: %s', app.get('url'));
    });
};

// start the server if `$ node server.js`
if (require.main === module) {
    app.start();
}
