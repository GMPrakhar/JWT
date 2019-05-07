const express = require('express')
const passport = require('passport')
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const errorHandler = require('errorhandler');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;
const oauth2orize = require('oauth2orize')
const login = require('connect-ensure-login')
const jwt = require('jsonwebtoken')
const passportJWT = require("passport-jwt");
const JWTStrategy   = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const app = express()
app.use(cookieParser());
app.use(bodyParser.json({ extended: false }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(errorHandler());
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());
var server =  oauth2orize.createServer()


passport.use(new JWTStrategy({
  jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
  secretOrKey   : 'jwtSecret'
},
function (jwtPayload, cb) {

  console.log(jwtPayload);
  //find the user in db if needed. This functionality may be omitted if you store everything you'll need in JWT payload.
  return cb(null, jwtPayload)
}
));



server.serializeClient((client, done) => done(null, 15));

server.deserializeClient((id, done) => {
    return done(null, client);
});

passport.serializeUser((user, done) =>  done(null, user.id));
  
  passport.deserializeUser((id, done) => {
    db.users.findById(id, (error, user) => done(error, user));
  });
  
  server.grant(oauth2orize.grant.code((client, redirectUri, user, ares, done) => {
    const code = "THISISACODE";
      return done(null, code);
  }));
  // Grant implicit authorization. The callback takes the `client` requesting
  // authorization, the authenticated `user` granting access, and
  // their response, which contains approved scope, duration, etc. as parsed by
  // the application. The application issues a token, which is bound to these
  // values.
  
  server.grant(oauth2orize.grant.token((client, user, ares, done) => {
    
    const token = jwt.sign(user, 'jwtSecret');
      return done(null, token);
  }));
  
  // Exchange authorization codes for access tokens. The callback accepts the
  // `client`, which is exchanging `code` and any `redirectUri` from the
  // authorization request for verification. If these values are validated, the
  // application issues an access token on behalf of the user who authorized the
  // code. The issued access token response can include a refresh token and
  // custom parameters by adding these to the `done()` call
  
  server.exchange(oauth2orize.exchange.code((client, code, redirectUri, done) => {
    
        let params = { username: "Shankar" };
        const token = jwt.sign({user: "Prakhar", userID: 100}, 'jwtSecret');
        // Call `done(err, accessToken, [refreshToken], [params])` to issue an access token
        return done(null, token, null, params);
  }));
  
  // Exchange user id and password for access tokens. The callback accepts the
  // `client`, which is exchanging the user's name and password from the
  // authorization request for verification. If these values are validated, the
  // application issues an access token on behalf of the user who authorized the code.
  
  server.exchange(oauth2orize.exchange.password((client, username, password, scope, done) => {
    // Validate the client
    const token = jwt.sign({user: "Prakhar", userID: 100}, 'jwtSecret');
          return done(null, token);
  }));
  
  // Exchange the client id and password/secret for an access token. The callback accepts the
  // `client`, which is exchanging the client's id and password/secret from the
  // authorization request for verification. If these values are validated, the
  // application issues an access token on behalf of the client who authorized the code.
  
  server.exchange(oauth2orize.exchange.clientCredentials((client, scope, done) => {
    // Validate the client
    const token = jwt.sign({user: "Prakhar", userID: 100}, 'jwtSecret');
        return done(null, token);
  }));
  


  app.get('/dialog/authorize', [
  server.authorization((clientId, redirectUri, done) => {
    return done(null, {clientId: clientId}, redirectUri);
  },
  (client, user, done) => {
    // Check if grant request qualifies for immediate approval
    return done(null, true);
  }),
  (request, response) => {
    response.render('dialog', { transactionId: request.oauth2.transactionID, user: request.user, client: request.oauth2.client });
  },
]);

// User decision endpoint.
//
// `decision` middleware processes a user's decision to allow or deny access
// requested by a client application. Based on the grant type requested by the
// client, the above grant middleware configured above will be invoked to send
// a response.

app.post('/dialog/authorize/decision', [
    server.decision(),
]);


// Token endpoint.
//
// `token` middleware handles client requests to exchange authorization grants
// for access tokens. Based on the grant type being exchanged, the above
// exchange middleware will be invoked to handle the request. Clients must
// authenticate when making requests to this endpoint.

app.post('/oauth/token', [
  server.token(),
  server.errorHandler(),
]);

app.get('/api/user', [
  passport.authenticate('jwt', {session:false}),
  (req, res)=>{
    res.json(req.user);
  }

])

app.listen(3000, function(){})