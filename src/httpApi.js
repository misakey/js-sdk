const fetch = require('node-fetch');
const FormData = require('form-data');

const { default: objectToSnakeCaseDeep } = require('@misakey/core/helpers/objectToSnakeCaseDeep');
const { default: objectToSnakeCase } = require('@misakey/core/helpers/objectToSnakeCase');
const { default: objectToCamelCaseDeep } = require('@misakey/core/helpers/objectToCamelCaseDeep');

const BASE_TARGET_DOMAIN = process.env.MISAKEY_SDK_BASE_TARGET_DOMAIN || 'misakey.com';
const API_URL_PREFIX = `https://api.${BASE_TARGET_DOMAIN}`;
const AUTH_URL_PREFIX = `https://auth.${BASE_TARGET_DOMAIN}`;

async function getDataTagID(dataTag, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/datatags?names=${dataTag}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  const body = await response.json();

  if (body.length === 0) {
    throw Error(`Datatag not found: ${dataTag}`);
  }

  return body[0].id;
}

async function postBox({
  orgId, dataSubject, datatagId, publicKey, keyShare, accessToken, title,
  invitationData, provisions,
}) {
  // data in the "crypto" part is a bit more difficult to convert to snake_case
  // so we do it ourself
  const crypto = {
    // value is just a string, no need to convert deep
    invitation_data: invitationData,
  }

  if (provisions) {
    // non-trivial conversion to snake_case
    crypto.provisions = Object.fromEntries(
      Object.entries(provisions).map(([identifier, provision]) => (
        // `objectToSnakeCaseDeep` would try to convert the identifier,
        // and it would mess it up
        [identifier, objectToSnakeCase(provision)]
      ))
    )
  }

  const requestJson = objectToSnakeCaseDeep(
    {
      title,
      ownerOrgId: orgId,
      dataSubject,
      datatagId,
      publicKey,
      keyShare,
      crypto,
    },
    { excludedKeys: ['crypto'] },
  );

  const response = await fetch(
    `${API_URL_PREFIX}/organizations/${orgId}/boxes`,
    {
      method: 'POST',
      body: JSON.stringify(requestJson),
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  const body = await response.json();

  return body;
}

/**
 * Encrypts message with box public key and posts it
 */
async function postTextMessage({ encryptedMessageContent, boxId, boxPublicKey, accessToken }) {
  const response = await fetch(
    `${API_URL_PREFIX}/boxes/${boxId}/events`,
    {
      method: 'POST',
      body: JSON.stringify({
        type: 'msg.text',
        content: {
          encrypted: encryptedMessageContent,
          public_key: boxPublicKey,
        },
      }),
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }
}

async function postFileMessage(
  encryptedFile, fileName, encryptedMsgContent,
  boxId, boxPublicKey, accessToken,
) {
  const form = new FormData();
  form.append(
    'encrypted_file',
    Buffer.from(encryptedFile),
    {
      filename: fileName,
    },
  );
  form.append('msg_encrypted_content', encryptedMsgContent);
  form.append('msg_public_key', boxPublicKey);

  const response = await fetch(
    `${API_URL_PREFIX}/boxes/${boxId}/encrypted-files`,
    {
      method: 'POST',
      body: form,
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }
}

async function getBoxMessages(boxId, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/boxes/${boxId}/messages`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  const body = await response.json();

  return body;
}

async function exchangeToken(orgId, authSecret) {
  const form = new FormData();
  form.append('grant_type', 'client_credentials');
  form.append('scope', '');
  form.append('client_id', orgId);
  form.append('client_secret', authSecret);

  const response = await fetch(
    `${AUTH_URL_PREFIX}/_/oauth2/token`,
    {
      method: 'POST',
      body: form,
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return (await response.json()).access_token;
}

async function getIdentifierPublicKey(identifier, authSecret) {
  const response = await fetch(
    `${API_URL_PREFIX}/identities/pubkey?identifier_value=${identifier}`,
    {
      headers: {
        Authorization: `Bearer ${authSecret}`,
      },
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCaseDeep(await response.json());
}

module.exports = {
  BASE_TARGET_DOMAIN,
  getDataTagID,
  postBox,
  postTextMessage,
  postFileMessage,
  getBoxMessages,
  exchangeToken,
  getIdentifierPublicKey,
};
