Implement OAuth2 for REST API in Loopback 2
==========================

## Installation

### 1. Install Strongloop (http://docs.strongloop.com/display/public/LB/Installing+StrongLoop)
Open your composer.json file and add the following lines:
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
<strong>client_id</strong> : from you Application ID
<strong>client_secret</strong> : from you Application restApiKey

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Authorization.png">

### 7. Test user login
Use basic auth, put your user email & password for the "Authorization Basic base64"
<strong>access_token</strong> : from authorization access_token response

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/User-Login.png">

### 7. Test get facilities data
Use "Authorization Bearer access_token"
<strong>access_token</strong> : from user login access_token response

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Get-Facilities.png">

### 7. Test refreshing token
<strong>refresh_token</strong> : from user login refresh_token response

<img src="https://dl.dropboxusercontent.com/u/1550865/loopback-api-base/Refresh-Token.png">
