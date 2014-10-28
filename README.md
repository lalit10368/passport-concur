# passport-concur

Fork of passport-oauth2 to provide Concur-specific OAuth 2.0 authentication strategy for [Passport](http://passportjs.org/).

This module lets you authenticate using Concur in your Node.js applications.
By plugging into Passport, Concur's OAuth 2.0 authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install

    $ npm install passport-concur

## Usage

#### Configure Strategy

The Concur authentication strategy authenticates users using a Concur
account and OAuth 2.0 tokens.  The strategy
requires a `verify` callback, which receives an access token and profile,
and calls `done` providing a user.

    passport.use(new ConcurStrategy({
        clientID: EXAMPLE_CLIENT_ID,
        clientSecret: EXAMPLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/example/callback"
      },
      function(accessToken, refreshToken, instanceUrl, expirationDate, done) {
        User.findOrCreate({ exampleId: profile.id }, function (err, user) {
          return done(err, user);
        });
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'concur'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/auth/example',
      passport.authenticate('concur'));

    app.get('/auth/example/callback',
      passport.authenticate('concur', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
      });

## Tests

    $ npm install
    $ npm test

## Credits

  - Forked from [passport-oauth2](https://github.com/jaredhanson/passport-github) by [Jared Hanson](https://github.com/jaredhanson)

## License

[The MIT License](http://opensource.org/licenses/MIT)