# Test scripts

Expected order:

1. `register.sh`: creates a test user `demo` with password `123456`
2. `login.sh`: login as the test user, creates `cookies` file with an auth token
3. `importspecs.sh`: imports test specs (mongo, girder) using auth cookie
4. `createstack.sh`: creates a new Girder userapp (girder + mongo) using auth cookie
5. `logout.sh`: logs user out and invalidates their existing cookie
