/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , querystring = require('querystring')
  , url = require('url')
  , uid = require('uid2')
  , util = require('util')
  , utils = require('./utils')
  , OAuth2 = require('oauth').OAuth2
  , AuthorizationError = require('./errors/authorizationerror')
  , TokenError = require('./errors/tokenerror')
  , InternalOAuthError = require('./errors/internaloautherror');

// Overloading required for getting the access token using URL instead of post data
var _getOAuthAccessToken = function(code, params, callback) {
  params= params || {};
  params['client_id'] = this._clientId;
  params['client_secret'] = this._clientSecret;
  var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
  params[codeParam]= code;

  var post_data= querystring.stringify( params );
  var post_headers= {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept':'application/json'
  };


  this._request("POST", this._getAccessTokenUrl() + '?' + post_data, post_headers, post_data, null, function(error, data, response) {
    if( error )  callback(error);
    else {
      var results;
      try {
        results= JSON.parse( data );
      }
      catch(e) {
        results= querystring.parse( data );
      }
      var access_token= results.Access_Token.Token;
      var refresh_token= results.Access_Token.Refresh_Token;
      var instance_url = results.Access_Token.Instance_Url;
      var expiration_date = results.Access_Token.Expiration_date;
      delete results.Access_Token.Refresh_Token;
      callback(null, access_token, refresh_token, instance_url, expiration_date, results); // callback results =-=
    }
  });
};


/**
 * Creates an instance of `ConcurStrategy`.
 *
 * The Concur authentication strategy authenticates requests using Concur's OAuth
 * 2.0 framework.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, refreshToken, profile, done) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * invoking `done` with the following arguments:
 *
 *     done(err, user, info);
 *
 * `user` should be set to `false` to indicate an authentication failure.
 * Additional `info` can optionally be passed as a third argument, typically
 * used to display informational messages.  If an exception occured, `err`
 * should be set.
 *
 * Options:
 *
 *   - 'consumerKey'       consumer key for Concur partner application
 *   - `clientID`          identifies client to service provider
 *   - `clientSecret`      secret used to establish ownership of the client identifier
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `passReqToCallback` when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new ConcurStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function ConcurStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  // Concur specific endpoints
  if (!options.authorizationURL) options.authorizationURL = 'https://www.concursolutions.com/net2/oauth2/Login.aspx';
  if (!options.tokenURL) options.tokenURL = 'https://www.concursolutions.com/net2/oauth2/GetAccessToken.ashx';
  
  if (!verify) { throw new TypeError('ConcurStrategy requires a verify callback'); }
  if (!options.clientID) { throw new TypeError('ConcurStrategy requires a clientID option'); }
  if (!options.clientSecret) { throw new TypeError('ConcurStrategy requires a clientSecret option'); }


  passport.Strategy.call(this);
  this.name = 'concur';
  this._verify = verify;

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
      '', options.authorizationURL, options.tokenURL, options.customHeaders);
  this._getOAuthAccessToken = _getOAuthAccessToken;
  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeparator = options.scopeSeparator || ' ';
  this._state = options.state;
  this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizationURL).hostname);
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(ConcurStrategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
ConcurStrategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  var oauth2Context = this._oauth2;
  if (req.query && req.query.error) {
    if (req.query.error == 'access_denied') {
      return this.fail({ message: req.query.error_description });
    } else {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }
  }
  
  var callbackURL = options.callbackURL || this._callbackURL;
  if (callbackURL) {
    var parsed = url.parse(callbackURL);
    if (!parsed.protocol) {
      // The callback URL is relative, resolve a fully qualified URL from the
      // URL of the originating request.
      callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
    }
  }
  
  if (req.query && req.query.code) {
    var code = req.query.code;
    
    if (this._state) {
      if (!req.session) { return this.error(new Error('ConcurStrategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      if (!req.session[key]) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      var state = req.session[key].state;
      if (!state) {
        return this.fail({ message: 'Unable to verify authorization request state.' }, 403);
      }
      
      delete req.session[key].state;
      if (Object.keys(req.session[key]).length === 0) {
        delete req.session[key];
      }
      
      if (state !== req.query.state) {
        return this.fail({ message: 'Invalid authorization request state.' }, 403);
      }
    }

    var params = this.tokenParams(options);
    params.grant_type = 'authorization_code';
    params.redirect_uri = callbackURL;

    this._getOAuthAccessToken.call(oauth2Context, code, params,
      function(err, accessToken, refreshToken, params) {
        if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
        
        self._loadUserProfile(accessToken, function(err, profile) {
          if (err) { return self.error(err); }
          
          function verified(err, user, info) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(info); }
            self.success(user, info);
          }
          
          try {
            if (self._passReqToCallback) {
              var arity = self._verify.length;
              if (arity == 6) {
                self._verify(req, accessToken, refreshToken, params, profile, verified);
              } else { // arity == 5
                self._verify(req, accessToken, refreshToken, profile, verified);
              }
            } else {
              var arity = self._verify.length;
              if (arity == 5) {
                self._verify(accessToken, refreshToken, params, profile, verified);
              } else { // arity == 4
                self._verify(accessToken, refreshToken, profile, verified);
              }
            }
          } catch (ex) {
            return self.error(ex);
          }
        });
      }
    );
  } else {
    var params = this.authorizationParams(options);
    params.response_type = 'code';
    params.redirect_uri = callbackURL;
    var scope = options.scope || this._scope;
    if (scope) {
      if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
      params.scope = scope;
    }
    var state = options.state;
    if (state) {
      params.state = state;
    } else if (this._state) {
      if (!req.session) { return this.error(new Error('ConcurStrategy requires session support when using state. Did you forget app.use(express.session(...))?')); }
      
      var key = this._key;
      state = uid(24);
      if (!req.session[key]) { req.session[key] = {}; }
      req.session[key].state = state;
      params.state = state;
    }
    
    var location = this._oauth2.getAuthorizeUrl(params);
    this.redirect(location);
  }
};

/**
 * Retrieve user profile from Concur.
 *
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
ConcurStrategy.prototype.userProfile = function(accessToken, done) {
  return done(null, {});
};

/**
 * Return extra parameters to be included in the authorization request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
ConcurStrategy.prototype.authorizationParams = function(options) {
  return {};
};

/**
 * Return extra parameters to be included in the token request.
 *
 *
 * @return {Object}
 * @api protected
 */
ConcurStrategy.prototype.tokenParams = function(options) {
  return {};
};

/**
 * Parse error response from OAuth 2.0 endpoint.
 *
 *
 * @param {String} body
 * @param {Number} status
 * @return {Error}
 * @api protected
 */
ConcurStrategy.prototype.parseErrorResponse = function(body, status) {
  var json = JSON.parse(body);
  if (json.error) {
    return new TokenError(json.error_description, json.error, json.error_uri);
  }
  return null;
};

/**
 * Load user profile, contingent upon options.
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api private
 */
ConcurStrategy.prototype._loadUserProfile = function(accessToken, done) {
  var self = this;
  
  function loadIt() {
    return self.userProfile(accessToken, done);
  }
  function skipIt() {
    return done(null);
  }
  
  if (typeof this._skipUserProfile == 'function' && this._skipUserProfile.length > 1) {
    // async
    this._skipUserProfile(accessToken, function(err, skip) {
      if (err) { return done(err); }
      if (!skip) { return loadIt(); }
      return skipIt();
    });
  } else {
    var skip = (typeof this._skipUserProfile == 'function') ? this._skipUserProfile() : this._skipUserProfile;
    if (!skip) { return loadIt(); }
    return skipIt();
  }
};

/**
 * Create an OAuth error.
 *
 * @param {String} message
 * @param {Object|Error} err
 * @api private
 */
ConcurStrategy.prototype._createOAuthError = function(message, err) {
  var e;
  if (err.statusCode && err.data) {
    try {
      e = this.parseErrorResponse(err.data, err.statusCode);
    } catch (_) {}
  }
  if (!e) { e = new InternalOAuthError(message, err); }
  return e;
};


/**
 * Expose `ConcurStrategy`.
 */
module.exports = ConcurStrategy;
