import RelyingPartyClientSdk from '@connectid-tools/rp-nodejs-sdk'
import jwt_decode from 'jwt-decode'
import fs from 'fs'
import path from 'path'
import express from 'express'
import https from 'https'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import winston from 'winston'
import { fileURLToPath } from 'url'
import { config } from './config.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const rpClient = new RelyingPartyClientSdk(config)
const logFormat = winston.format.printf(({ level, message, timestamp }) => `${timestamp} ${level}: ${message}`)
const logger = winston.createLogger({
  level: config.data.log_level || 'info',
  format: winston.format.combine(winston.format.colorize(), winston.format.timestamp(), logFormat),
  transports: [new winston.transports.Console({ colorize: true })],
})


var g_state = "";
var g_nonce = "";
var g_codeVerifier = "";
var g_authorisation_server_id = "";

var ah_state = "";

const app = express()
app.use(cookieParser())
app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

app.use(express.urlencoded({ extended: false }));

const clearCookies = (res) => {
  logger.info('Clearing all cookies')
  res.clearCookie('state')
  res.clearCookie('nonce')
  res.clearCookie('code_verifier')
}

app.get("/rp/logo.png", (req, res) => {
  clearCookies(res)
  res.sendFile(__dirname + '/logo.png');
});   

app.get('/', (_, res) => {
  clearCookies(res)
  res.sendFile(__dirname + '/index.html')
})

app.get('/custom', (_, res) => {
  clearCookies(res)
  res.sendFile(__dirname + '/custom.html')
})

app.get('/cb', (_, res) => {
  res.sendFile(__dirname + '/result.html')
})

// Handle the user's bank selection and start the OIDC flow.
// Create a Pushed Authorization Request (PAR) with the claims
// required and then return the bank redirect url to authenticate.
app.get('/rp/authorize', async (req, res) => {
  const essentialClaims = req.query.essentialClaims || config.data.required_claims
  const voluntaryClaims = req.query.voluntaryClaims || []
  const purpose = req.query.purpose || config.data.purpose
  const authServerId = req.query.authorisationServerId || config.data.authorization_server_id

  console.log ("AUTHORIZE: ");
  console.log ("   ---   QUERY : ", req.query);

  ah_state = req.query['state'];
  console.log ("   ---   X-FLOW-STATE = ", ah_state);
  
  if (!authServerId) {
    const error = 'authorisationServerId parameter is required'
    logger.error(error)
    return res.status(400).json({ error })
  }

  try {
    logger.info(
      `Processing request to send PAR with authorisationServerId='${authServerId}' essentialClaims='${essentialClaims.join(
        ','
      )}' voluntaryClaims='${voluntaryClaims.join(',')}', purpose='${purpose}'`
    )
    const { authUrl, code_verifier, state, nonce, xFapiInteractionId } = await rpClient.sendPushedAuthorisationRequest(
      authServerId,
      essentialClaims,
      voluntaryClaims,
      purpose
    )

    const path = ''
    res.cookie('state', state, { path, sameSite: 'none', secure: true })
    res.cookie('nonce', nonce, { path, sameSite: 'none', secure: true })
    res.cookie('code_verifier', code_verifier, { path, sameSite: 'none', secure: true })
    res.cookie('authorisation_server_id', authServerId, { path, sameSite: 'none', secure: true })
    g_state = state;
    g_nonce = nonce;
    g_codeVerifier = code_verifier;
    g_authorisation_server_id = authServerId;

    logger.info(`PAR sent to authorisationServerId='${authServerId}', returning url='${authUrl}', x-fapi-interaction-id='${xFapiInteractionId}'`)

    return res.redirect( authUrl )
  } catch (error) {
    logger.error(error)
    return res.status(500).json({ error: error.toString() })
  }
})

// Following successful authentication and consent at the bank, the user's browser will be redirected
// back to the callback URL using a get request, with the auth code contained as in the query string
// parameter `code`. Exchange the auth token for an ID Token.
app.get('/retrieve-tokens', async (req, res) => {
  // If the callback url was requested without a code token, just clear any
  // stale cookies and load the default landing page
  if (!req.query.code) {
    clearCookies(res)
    return res.status(400).json({ error: 'No code parameter in query string' })
  }

  try {
    const tokenSet = await rpClient.retrieveTokens(
      req.cookies.authorisation_server_id,
      req.query,
      req.cookies.code_verifier,
      req.cookies.state,
      req.cookies.nonce
    )
    const claims = tokenSet.claims()
    const token = {
      decoded: JSON.stringify(jwt_decode(tokenSet.id_token), null, 2),
      raw: tokenSet.id_token,
    }

    logger.info(`Returned claims: ${JSON.stringify(claims, null, 2)}`)
    logger.info(`Returned raw id_token: ${token.raw}`)
    logger.info(`Returned decoded id_token: ${token.decoded}`)
    logger.info(`Returned xFapiInteractionId: ${tokenSet.xFapiInteractionId}`)

    return res.json({ claims, token, xFapiInteractionId: tokenSet.xFapiInteractionId })
  } catch (error) {
    logger.error('Error retrieving tokenset: ' + error)
    return res.status(500).json({ error: error.toString() })
  }
})

app.get('/rp/callback', (req, res) => {
   var callbackPath = "https://ssp.iamdemo.broadcom.com/default/oauth2/v1/rp/callback";
   console.log("CALLBACK ");
   console.log("   ---  INCOMING QUERY : ",  req.query);
   var callbackUrl = callbackPath + "?code=" + req.query.code + "&state=" + ah_state;
   console.log("   ---   REDIRECTING TO = ", callbackUrl);

   res.redirect( callbackUrl )

});


app.post('/rp/token', async (req, res) => {
  // If the callback url was requested without a code token, just clear any
  // stale cookies and load the default landing page
  console.log("TOKEN CALL --- HEADERS \n",req.headers);
  req.body['state'] = g_state;
  req.body['iss'] = "https://auth.bank2.directory.sandbox.connectid.com.au";
  console.log("TOKEN CALL --- BODY  \n",req.body);
  if (!req.body.code) {
    clearCookies(res)
    return res.status(400).json({ error: 'No code parameter in query string' })
  }


  try {
    const tokenSet = await rpClient.retrieveTokens(
      g_authorisation_server_id,
      req.body,
      g_codeVerifier,
      g_state,
      g_nonce
    )
    const claims = tokenSet.claims()
    const token = {
      decoded: JSON.stringify(jwt_decode(tokenSet.id_token), null, 2),
      raw: tokenSet.id_token,
    }

    logger.info(`Returned claims: ${JSON.stringify(claims, null, 2)}`)
    logger.info(`Returned raw id_token: ${token.raw}`)
    logger.info(`Returned decoded id_token: ${token.decoded}`)
    logger.info(`Returned xFapiInteractionId: ${tokenSet.xFapiInteractionId}`)

    console.log("   ---   TOKENSET :", tokenSet);
    //console.log("   ---   RETURNING :");
    //console.log({ claims, token, xFapiInteractionId: tokenSet.xFapiInteractionId });

    //return res.json({ claims, token, xFapiInteractionId: tokenSet.xFapiInteractionId })
    return  res.json (tokenSet);
  } catch (error) {
    logger.error('Error retrieving tokenset: ' + error)
    return res.status(500).json({ error: error.toString() })
  }
})
//const key = fs.readFileSync(path.resolve(__dirname + '/..', config.data.transport_key))
//const cert = fs.readFileSync(path.resolve(__dirname + '/..', config.data.transport_pem))
const key = fs.readFileSync(path.resolve(__dirname + '/../certs/iamdemo.key'));
const cert = fs.readFileSync(path.resolve(__dirname + '/../certs/iamdemo.pem'));
https.createServer({ key, cert }, app).listen(config.data.server_port, config.data.listen_address)

logger.info(`rp-nodejs-sample-app started on ${config.data.listen_address} on port ${config.data.server_port}`)
