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

const app = express()
app.use(cookieParser())
app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

const clearCookies = (res) => {
  logger.info('Clearing all cookies')
  res.clearCookie('state')
  res.clearCookie('nonce')
  res.clearCookie('code_verifier')
}

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
app.post('/select-bank', async (req, res) => {
  const essentialClaims = req.body.essentialClaims || []
  const voluntaryClaims = req.body.voluntaryClaims || []
  const purpose = req.body.purpose || config.data.purpose
  const authServerId = req.body.authorisationServerId
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

    logger.info(`PAR sent to authorisationServerId='${authServerId}', returning url='${authUrl}', x-fapi-interaction-id='${xFapiInteractionId}'`)

    return res.json({ authUrl })
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

const key = fs.readFileSync(path.resolve(__dirname + '/..', config.data.transport_key))
const cert = fs.readFileSync(path.resolve(__dirname + '/..', config.data.transport_pem))
https.createServer({ key, cert }, app).listen(config.data.server_port, config.data.listen_address)

logger.info(`rp-nodejs-sample-app started on ${config.data.listen_address} on port ${config.data.server_port}`)
