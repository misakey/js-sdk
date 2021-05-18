const fetch = require('node-fetch');
const FormData = require('form-data');

const { default: objectToSnakeCase } = require('@misakey/core/helpers/objectToSnakeCase');
const { default: objectToCamelCase } = require('@misakey/core/helpers/objectToCamelCase');
const { default: objectToSnakeCaseDeep } = require('@misakey/core/helpers/objectToSnakeCaseDeep');
const { default: objectToCamelCaseDeep } = require('@misakey/core/helpers/objectToCamelCaseDeep');
const { default: snakeCase } = require('@misakey/core/helpers/snakeCase');
const { default: isNil } = require('@misakey/core/helpers/isNil');
const { default: isEmpty } = require('@misakey/core/helpers/isEmpty');

const BASE_TARGET_DOMAIN_DEFAULT = `misakey.com${process.env.NODE_ENV === 'production' ? '' : '.local'}`;
const BASE_TARGET_DOMAIN = process.env.MISAKEY_SDK_BASE_TARGET_DOMAIN || BASE_TARGET_DOMAIN_DEFAULT;
const API_URL_PREFIX = `https://api.${BASE_TARGET_DOMAIN}`;
const AUTH_URL_PREFIX = `https://auth.${BASE_TARGET_DOMAIN}`;


async function getDataTagCrypto(dataTag, dataSubject, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/datatags/crypto?datatag_name=${dataTag}&data_subject=${dataSubject}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  const responseJson = await response.json();

  const {
    datatag: {
      id: datatagId,
    },
    dataSubjectIdentityPublicKeys: {
      cryptoProvisions,
      identityPubkey,
    },
    consentPublicKey,
  } = objectToCamelCaseDeep(responseJson);

  return {
    datatagId,
    cryptoProvisions,
    identityPubkey,
    consentPublicKey,
  }
}

async function postBox({
  orgId, title, dataSubject, datatagId,
  publicKey, consentEncryptedSecretKey,
  keyShare,
  invitationData, provisions, newConsentKey,
  accessToken,
}) {
  // data in the "crypto" part is a bit more difficult to convert to snake_case
  // so we do it ourself
  const crypto = {
    // value is just a string, no need to convert deep
    invitation_data: invitationData,
  };

  if (!isEmpty(provisions)) {
    // non-trivial conversion to snake_case
    crypto.provisions = Object.fromEntries(
      Object.entries(provisions).map(([identifier, provision]) => (
        // `objectToSnakeCaseDeep` would try to convert the identifier,
        // and it would mess it up
        [identifier, objectToSnakeCase(provision)]
      ))
    );
  }

  if (!isEmpty(newConsentKey)) {
    // this case conversion, however, is trivial
    crypto.new_consent_key = objectToSnakeCaseDeep(newConsentKey);
  }

  const requestJson = objectToSnakeCaseDeep(
    {
      title,
      ownerOrgId: orgId,
      dataSubject,
      datatagId,
      publicKey,
      consentEncryptedSecretKey,
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

async function exchangeToken(body) {
  const response = await fetch(
    `${AUTH_URL_PREFIX}/_/oauth2/token`,
    {
      method: 'POST',
      body,
    },
  );

  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCase(await response.json());
}


async function exchangeOrgToken(orgId, authSecret) {
  const form = new FormData();
  form.append('grant_type', 'client_credentials');
  form.append('scope', '');
  form.append('client_id', orgId);
  form.append('client_secret', authSecret);

  const { accessToken } = await exchangeToken(form);
  return accessToken;
}

async function exchangeUserToken(body) {
  const form = new FormData();
  form.append('grant_type', 'authorization_code');
  
  Object.entries(body).forEach(([key, value]) => {
    if (!isNil(value)) {
      form.append(snakeCase(key), value);
    }
  });

  return exchangeToken(form);
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

async function getSecretStorage(accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/crypto/secret-storage`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )
  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCaseDeep(await response.json(), { ignoreBase64: true });
}

async function getIdentity(identityId, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/identities/${identityId}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )
  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCaseDeep(await response.json());
}

async function getCryptoActions(accountId, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/accounts/${accountId}/crypto/actions`,
    {
      headers: {
        // TODO stop using CSRF token
        // when backend allows it (see https://gitlab.misakey.dev/misakey/backend/-/merge_requests/382)
        'X-CSRF-Token': 'valueDoesNotMatter',
        Cookie: `_csrf=valueDoesNotMatter; accesstoken=${accessToken}; tokentype=bearer`,
      }
    }
  )
  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCaseDeep(await response.json());
}

async function listBoxes(dataSubject, datatagId, producerOrgId, accessToken) {
  const response = await fetch(
    `${API_URL_PREFIX}/boxes?data_subject=${dataSubject}&datatag_ids=${datatagId}&owner_org_id=${producerOrgId}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  )
  if (!response.ok) {
    const error = new Error();
    error.response = response;
    throw error;
  }

  return objectToCamelCaseDeep(await response.json());
}

module.exports = {
  BASE_TARGET_DOMAIN,
  AUTH_URL_PREFIX,
  getDataTagCrypto,
  postBox,
  postTextMessage,
  postFileMessage,
  getBoxMessages,
  getIdentifierPublicKey,
  exchangeOrgToken,
  exchangeUserToken,
  getSecretStorage,
  getIdentity,
  getCryptoActions,
  listBoxes,
};
