const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");

const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
var jwtAuthz = require('express-jwt-authz');

const authConfig = require("./src/auth_config.json");

const app = express();

const port = process.env.API_PORT || 3001;
const appPort = process.env.SERVER_PORT || 3000;
const appOrigin = authConfig.appOrigin || `http://localhost:${appPort}`;

if (
  !authConfig.domain ||
  !authConfig.audience ||
  authConfig.audience === ""
) {
  console.log(
    "Exiting: Please make sure that auth_config.json is in place and populated with valid domain and audience values"
  );

  process.exit();
}

app.use(morgan("dev"));
app.use(helmet());
app.use(cors({ origin: appOrigin }));

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ["RS256"],
});


console.log(checkJwt.name);
// anyone who has logged in can access this end point
app.get("/api/external", checkJwt, (req, res) => {
  res.send({
    msg: "Your access token was successfully validated!",
  });
});

// validate a JWT and make sure it has the correct permissions to call an endpoint
app.get("/api/externalwithscope", checkJwt, jwtAuthz(['edit:imagetry','read:health'],  {customScopeKey: "permissions" }),  (req, res) => {
  res.send({
    msg:"You have edit:image permission/scope for this end point."
  });
});
// validate a JWT and make sure it has the correct permissions to call an endpoint
app.get("/api/externalallscope", checkJwt, jwtAuthz(['edit:image'],{ customScopeKey: "permissions" }), (req,res) =>
{
  res.send({
    msg:"You have all scopes granted."
  });
});


app.listen(port, () => console.log(`API Server listening on port ${port}`));
