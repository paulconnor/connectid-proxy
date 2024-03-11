import fs from 'fs'

export const config = {
  data: {

    // Picked up from the .wellknown/discovery endpoint for bank2
    authorizaton_server_id: 'abd2a7e0-ebdf-4302-b059-d8878d1ef41a',

    // Set the signing Key Id based on what is contained in the JWKS
    signing_kid: '_s4TKlBnRSP6CNaL3DiqP83VeyZNUtdIHZsAce6lhdc',

    // The location of the transport certificate and key that are used for mutual TLS
    transport_key: './certs/transport-dev.key',
    transport_pem: './certs/transport-dev.pem',

    // The location of the signing certificate and key that are used for signing purposes
    // The example below shows how the signing key can be provided as a string rather than as a file reference
    // Note this method can be used for each of the keys and pem files - which can be useful if values are
    // being provided from a vault / secrets manager rather than being read directly from a file.
    //signing_key: './certs/signing.key',
    signing_key_content: fs.readFileSync('./certs/signing-dev.key').toString(),
    signing_pem: './certs/signing-dev.pem',
    //

    // The location of the root certificate for the trust authority
    ca_pem: './certs/connectid-sandbox-ca.pem',

    // This is the URL that this application is actually running on and using for callbacks (noting that multiple may be registered for the client)
    //application_redirect_uri: 'https://tpp.localhost/cb',
    //application_redirect_uri: 'https://ssp.iamdemo.broadcom.com/default/oauth2/v1/rp/callback',
    application_redirect_uri: 'https://connectid.iamdemo.broadcom.com/rp/callback',

    // The port that the rp-connector will listen on
    server_port: '443',

    // The interfaces the server will listen on. 0.0.0.0 will bind to all interfaces.
    listen_address: '0.0.0.0',

    // The application logging level (info - normal logging, debug - full request/response)
    // This MUST not be set to debug in a production environment as it will log all personal data received
    log_level: 'debug',

    // When running the OIDC FAPI compliance suite, it requires a call to user info after successfully decoding the
    // response claims. If this is set to true, the SDK will automatically make the call.
    enable_auto_compliance_verification: false,

    // The registry API endpoint that will list all participants with their auth server details
    registry_participants_uri: 'https://data.directory.sandbox.connectid.com.au/participants',

    // This will ensure that all participants are returned, regardless of their certification status
    // and any `required_claims` or `required_participant_certifications` requirements.
    // This should be set to false in a production environment, only enable for testing.
    // If not provided, will default to false.
    // This is only set to true in the sample app so we can use it to test uncertified participants.
    include_uncertified_participants: true,

    // Configuring `required_participant_certifications` will ensure that the participants returned are only those
    // with the required certifications. Participants must have all specified certifications to be included.
    // Note that if `include_uncertified_participants` is set to true, this will be ignored.
    // As an example, if you require the IDPs to have TDIF certification as part of your use case, you
    // can filter for: `[{ profileType: 'TDIF Accreditation', profileVariant: 'Identity Provider' }]
    // required_participant_certifications: [
    //   { profileType: 'TDIF Accreditation', profileVariant: 'Identity Provider' },
    // ],

    // The list of claims that authorisation servers must support to be included in the list of participants
    // If this is not provided, no filtering based on claims will be performed
    // Note that if `include_uncertified_participants` is set to true, this will be ignored.
    required_claims: ['name', 'given_name', 'middle_name', 'family_name', 'phone_number', 'email', 'birthdate'],


    // The purpose to be displayed to the consumer to indicate why their data is being requested to be shared
    // Must be between 3 and 300 chars and not contain any of the following characters: <>(){}'\
    purpose: 'Your data is being requested to be shared with the ConnectID Developer Tools Sample App for the purposes of demonstrating an end to end flow.',

    client: {
      // Update with your client specific metadata. The client_id and organisation_id can be found in the registry.
      client_id: 'https://rp.directory.sandbox.connectid.com.au/openid_relying_party/c9cae39c-4389-4f1a-963e-0159e46b654c',
      organisation_id: '7152e422-09df-4c31-bfef-e2f2675ecc5d',
      jwks_uri:
        'https://keystore.directory.sandbox.connectid.com.au/7152e422-09df-4c31-bfef-e2f2675ecc5d/c9cae39c-4389-4f1a-963e-0159e46b654c/application.jwks',
      redirect_uris: ['https://demo.use-cases.sandbox.connectid.com.au/cb', 'https://tpp.localhost/cb'],
      organisation_name: 'ConnectID Developer Tools Sample App',
      organisation_number: 'ABN123123123',
      software_description: 'App to demonstrate ConnectID end to end flows.',

      // The following config is here for reference - you should not need to change any of it
      application_type: 'web',
      grant_types: ['client_credentials', 'authorization_code', 'implicit'],
      id_token_signed_response_alg: 'PS256',
      post_logout_redirect_uris: [],
      require_auth_time: false,
      response_types: ['code id_token', 'code'],
      subject_type: 'public',
      token_endpoint_auth_method: 'private_key_jwt',
      token_endpoint_auth_signing_alg: 'PS256',
      introspection_endpoint_auth_method: 'private_key_jwt',
      revocation_endpoint_auth_method: 'private_key_jwt',
      request_object_signing_alg: 'PS256',
      require_signed_request_object: true,
      require_pushed_authorization_requests: true,
      authorization_signed_response_alg: 'PS256',
      tls_client_certificate_bound_access_tokens: true,
      backchannel_user_code_parameter: false,
      scope: 'openid',
      software_roles: ['RP-CORE'],
    },
  },
}
