var express = require('express');
var router = express.Router();

/* GET home page. */
// router.get('/', function(req, res, next) {
//   res.render('index', { title: 'Express' });
// });

var msal = require('@azure/msal-node');
var axios = require('axios');
require('dotenv').config();

/**
 * Configuration object to be passed to MSAL instance on creation.
 * For a full list of MSAL Node configuration parameters, visit:
 * https://github.com/AzureAD/microsoft-authentication-library-for-js/blob/dev/lib/msal-node/docs/configuration.md
 */
const msalConfig = {
  auth: {
    clientId: process.env.CLIENT_ID, // 'Application (client) ID' of app registration in Azure portal - this value is a GUID
    authority: process.env.CLOUD_INSTANCE + process.env.TENANT_ID, // Full directory URL, in the form of https://login.microsoftonline.com/<tenant>
    clientSecret: process.env.CLIENT_SECRET, // Client secret generated from the app registration in Azure portal
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message, containsPii) {
        console.log(message);
      },
      piiLoggingEnabled: false,
      logLevel: 'Info',
    },
  },
};

const REDIRECT_URI = process.env.REDIRECT_URI;

const msalInstance = new msal.ConfidentialClientApplication(msalConfig);
const cryptoProvider = new msal.CryptoProvider();

async function redirectToAuthCodeUrl(
  req,
  res,
  next,
  authCodeUrlRequestParams,
  authCodeRequestParams
) {
  console.log('req.cookies', req.cookies);
  // Generate PKCE Codes before starting the authorization flow
  const { verifier, challenge } = await cryptoProvider.generatePkceCodes();

  // Set generated PKCE codes and method as session vars
  req.session.pkceCodes = {
    challengeMethod: 'S256',
    verifier: verifier,
    challenge: challenge,
  };

  req.session.authCodeUrlRequest = {
    redirectUri: REDIRECT_URI,
    responseMode: 'form_post', // recommended for confidential clients
    codeChallenge: req.session.pkceCodes.challenge,
    codeChallengeMethod: req.session.pkceCodes.challengeMethod,
    ...authCodeUrlRequestParams,
  };

  req.session.authCodeRequest = {
    redirectUri: REDIRECT_URI,
    code: '',
    ...authCodeRequestParams,
  };

  // Get url to sign user in and consent to scopes needed for application
  try {
    const authCodeUrlResponse = await msalInstance.getAuthCodeUrl(
      req.session.authCodeUrlRequest
    );
    res.redirect(authCodeUrlResponse);
  } catch (error) {
    next(error);
  }
}

router.get('/go', async function (req, res, next) {
  session = req.session;
  console.log('aaaaa', req.query);

  res.cookie(`path`, req?.query?.path);
  console.log('cryptoProvider', cryptoProvider);
  // create a GUID for crsf
  req.session.csrfToken = cryptoProvider.createNewGuid();
  console.log('req.cookies', req.cookies.path);
  res.cookie(`csrfToken`, cryptoProvider.createNewGuid());
  const state = cryptoProvider.base64Encode(
    JSON.stringify({
      csrfToken: req.session.csrfToken,
      redirectTo: '/',
    })
  );

  const authCodeUrlRequestParams = {
    state: state,
    scopes: [],
  };

  const authCodeRequestParams = {
    scopes: [],
  };

  // trigger the first leg of auth code flow
  return redirectToAuthCodeUrl(
    req,
    res,
    next,
    authCodeUrlRequestParams,
    authCodeRequestParams
  );
});

router.post('/login', async function (req, res, next) {
  let reponse = '';
  console.log(req.cookies);
  if (req.body.state) {
    const state = JSON.parse(cryptoProvider.base64Decode(req.body.state));

    // check if csrfToken matches
    if (state.csrfToken === req.session.csrfToken) {
      req.session.authCodeRequest.code = req.body.code; // authZ code
      req.session.authCodeRequest.codeVerifier = req.session.pkceCodes.verifier; // PKCE Code Verifier

      try {
        const tokenResponse = await msalInstance.acquireTokenByCode(
          req.session.authCodeRequest
        );
        req.session.accessToken = tokenResponse.accessToken;
        req.session.idToken = tokenResponse.idToken;
        req.session.account = tokenResponse.account;
        req.session.isAuthenticated = true;

        res.redirect(state.redirectTo);
        var data = {
          client_id: process.env.CLIENT_ID,
          client_secret: process.env.CLIENT_SECRET,
          code: req.session.authCodeRequest.code,
          code_verifier: req.session.authCodeRequest.codeVerifier,
          grant_type: 'authorization_code',
          redirect_uri: process.env.REDIRECT_URI,
          scope: 'https%3A%2F%2Fads.microsoft.com%2Fmsads.manage',
          tenant: process.env.TENANT_ID,
        };
        var config = {
          method: 'post',
          url: 'https://login.microsoftonline.com/4ebc9261-871a-44c5-93a5-60eb590917cd/oauth2/v2.0/token',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          data: data,
        };

        axios(config)
          .then(function (response) {
            console.log(JSON.stringify(response.data));
            reponse = response.data;
          })
          .catch(function (error) {
            console.log(error);
          });
      } catch (error) {
        next(error);
      }
    } else {
      next(new Error('csrf token does not match'));
    }
  } else {
    next(new Error('state is missing'));
  }

  res.render('index', {
    accessToken: req.session.accessToken,
    code: req.session.authCodeRequest.code,
    reponse,
  });
});

router.post('/refresh', async function (req, res, next) {
  console.log(res?.body);
  let refresh_token = res?.query?.refresh_token || '';
  var data = {
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    refresh_token: refresh_token,
    grant_type: 'refresh_token',
    scope: 'https%3A%2F%2Fads.microsoft.com%2Fmsads.manage',
    tenant: process.env.TENANT_ID,
  };
  var config = {
    method: 'post',
    url: 'https://login.microsoftonline.com/4ebc9261-871a-44c5-93a5-60eb590917cd/oauth2/v2.0/token',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    data: data,
  };

  axios(config)
    .then(function (response) {
      console.log(JSON.stringify(response.data));
      reponse = response.data;
    })
    .catch(function (error) {
      console.log(error);
    });
});

// router.get('/signout', function (req, res) {
//     /**
//      * Construct a logout URI and redirect the user to end the
//      * session with Azure AD. For more information, visit:
//      * https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request
//      */
//     const logoutUri = `${msalConfig.auth.authority}/oauth2/v2.0/logout?post_logout_redirect_uri=${POST_LOGOUT_REDIRECT_URI}`;

//     req.session.destroy(() => {
//         res.redirect(logoutUri);
//     });
// });

module.exports = router;
