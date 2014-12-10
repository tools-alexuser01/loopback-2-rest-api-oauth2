Implement OAuth2 for REST API in Loopback 2
==========================

## Installation

### 1. Install Strongloop
Complete instruction on how to install Strongloop can be found at http://docs.strongloop.com/display/public/LB/Installing+StrongLoop
```
$ npm install -g strongloop
```

### 2. Install dependencies
```
$ npm install
```

### 3. Define your datasource
Currently tested using MongoDB. Define it at "/server/datasources.json" file.

### 4. Migrate required models to your datasource
Run following code to migrate required models at "/server/server.js" file. You can find the existing code there. Only run it one time, to make sure existing data does not removed.
```
app.dataSources.db.automigrate([
    'User', 
    'Application', 
    'Role', 
    'ACL', 
    'RoleMapping', 
    'AccessToken', 
    'OAuthScope', 
    'OAuthSession', 
    'OAuthSessionAccessToken', 
    'OAuthSessionRefreshToken', 
    'OAuthSessionTokenScope'
]);
```

### 5. Create basic OAuth scopes
Run following code to create the basic OAuth scopes for your client at "/server/server.js" file. You can find the existing code there. Only run it one time, to make sure no duplicate data.
```
app.models.OAuthScope.create({
    id: 'read',
    name: 'Read',
    description: 'Read access'
});

app.models.OAuthScope.create({
    id: 'write',
    name: 'Write',
    description: 'Write access'
});
```

### 5. Create a user and client
Run following code to create a user and client to test at "/server/server.js" file. You can find the existing code there. Only run it one time, to make sure no duplicate data.
```
app.models.User.create({
    username: 'sulaeman',
    email: 'me@sulaeman.com',
    password: 'sulaeman'
}, function(err, user) {
    if (err) {
        console.log(err);
    } else {
        app.models.Application.create({
            name: 'Default',
            owner: user.id,
            email: 'me@sulaeman.com',
            emailVerified: true
        }, function(err, application) {
            if (err) {
                console.log(err);
            } else {
                console.log(application);
            }
        });
    }
});
```

### 6. Test authorization
<p><strong>client_id</strong> : from you Application ID</p>
<p><strong>client_secret</strong> : from you Application restApiKey</p>

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Authorization.png">

### 7. Test user login
<p>Use basic auth, put your user email & password for the "Authorization Basic base64"</p>
<p><strong>access_token</strong> : from authorization access_token response</p>

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/User-Login.png">

### 7. Test get facilities data
<p>This endpoint can only be accessed by logged user, you can found how to check if the access_token related with logged user at "/server/methods/facilities/index.js" file</p>
<p>The user information passed in <strong>request</strong> object : <strong>req.authUser</strong></p>
<p>Use "Authorization Bearer access_token"</p>
<p><strong>access_token</strong> : from user login access_token response</p>

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Get-Facilities.png">

### 7. Test refreshing token
<strong>refresh_token</strong> : from user login refresh_token response</p>

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Refresh-Token.png">

## Code Usage
The OAuth implemented in "/server/boot/authenticaton.js" file.
```
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
```

## Client & User info
You can get the client and user info if client passing the access_token (Bearer Strategy) in the request at "request" object :
```
req.authClient;
req.authInfo;
req.authUser;
```