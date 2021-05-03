const mime = require('mime-types');

const { default: isArray } = require('@misakey/core/helpers/isArray');
const { default: isEmpty } = require('@misakey/core/helpers/isEmpty');
const { default: assertNotAnyNil } = require('@misakey/core/crypto/helpers/assertNotAnyNil');

const { createCryptoForNewBox } = require('@misakey/core/crypto/box/creation');
const { default: encryptText } = require('@misakey/core/crypto/box/encryptText');
const { default: encryptFile } = require('@misakey/core/crypto/box/encryptFile');
const { encryptCryptoaction } = require('@misakey/core/crypto/cryptoactions');
const { generateAsymmetricKeyPair } = require('@misakey/core/crypto/crypto');
const { splitKey } = require('@misakey/core/crypto/crypto/keySplitting');
const { default: isNil } = require('@misakey/core/helpers/isNil');
const { default: validateProperties } = require('@misakey/core/helpers/validateProperties');
const { default: log } = require('@misakey/core/helpers/log');

const httpApi = require('../httpApi');

async function createBox({
  title, dataSubject, dataTag,
  dataSubjectPublicKey, provisionPayload,
  orgId, accessToken,
}) {
  const datatagId = await httpApi.getDataTagID(dataTag, accessToken);

  const {
    boxPublicKey,
    boxSecretKey,
    invitationKeyShare,
    misakeyKeyShare,
  } = createCryptoForNewBox();

  const invitationData = {
    [dataSubjectPublicKey]: encryptCryptoaction(
      { boxSecretKey },
      dataSubjectPublicKey,
    )
  };

  let provisions;
  if (!isEmpty(provisionPayload)) {
    // making sure we don't include the user key share
    // (would break end-to-end encryption)
    // even if caller included it by mistake
    const { publicKey, misakeyKeyShare, userKeyShareHash } = provisionPayload;

    provisions = {
      [dataSubject]: { publicKey, misakeyKeyShare, userKeyShareHash },
    };
  }

  const box = await httpApi.postBox({
    orgId,
    dataSubject,
    datatagId,
    publicKey: boxPublicKey,
    keyShare: misakeyKeyShare,
    accessToken,
    title,
    invitationData,
    provisions,
  });

  return {
    boxId: box.id,
    datatagId,
    boxPublicKey,
    invitationKeyShare,
  };
}


async function getPublicKey(dataSubject, secrets, accessToken) {
  const {
    cryptoProvisions,
    identityPubkey,
  } = await httpApi.getIdentifierPublicKey(dataSubject, accessToken);

  if (identityPubkey) {
    return {
      publicKey: identityPubkey,
      provision: null,
    };
  }

  for (const provision of (cryptoProvisions || [])) {
    const { publicKey } = provision;
    const userKeyShare =  secrets.provisionsUserKeyShares[publicKey];

    if (userKeyShare) {
      return {
        publicKey,
        provision: {
          userKeyShare,
        }
      };
    }
  }

  // no existing provision worked: we create a new one
  const provision = createNewProvisionMaterial();
  const publicKey = provision.publicKey;
  secrets.provisionsUserKeyShares[publicKey] = provision.userKeyShare;
  return {
    publicKey,
    provision,
  };
}

// TODO move to @misakey/core
function createNewProvisionMaterial() {
  const { secretKey, publicKey } = generateAsymmetricKeyPair();

  const {
    userShare: userKeyShare,
    // XXX naming of shares is not very consistent
    // from one part of the code to the other
    // TODO fix this as part of refacto (https://gitlab.misakey.dev/misakey/frontend/-/issues/856)
    misakeyShare: {
      misakeyShare: misakeyKeyShare,
      userShareHash: userKeyShareHash,
    },
  } = splitKey(secretKey);

  return {
    publicKey,
    userKeyShare,
    creationPayload: {
      publicKey,
      misakeyKeyShare,
      userKeyShareHash,
    }
  };
}

class MisakeyServer {
  constructor(orgId, authSecret) {
    const err = validateProperties({ orgId, authSecret });
    if (err) { throw err; }

    this.orgId = orgId;
    this.authSecret = authSecret;
    this.accessToken = null;
    this.secrets = {
      // mapping from public key to user key share
      provisionsUserKeyShares: {},
    };
  }

  async exchangeUserToken(params, { client: clientRedirectUrl, server: redirectUri } = {}) {
    const paramsError = validateProperties({ params, redirectUri });
    if (paramsError) { return Promise.reject(paramsError); }

    const { error, errorDebug, errorHint, code, state, codeVerifier, scope } = params;

    if (!isNil(error)) {
      const description = isNil(errorDebug) ? errorHint : errorDebug;
      throw new Error(`${error} - ${description}`);
    }

    const err = validateProperties({ state, code });
    if (err) { return Promise.reject(err); }

    const scopes = scope.split(' ');
    // ensure `openid` scope is part of the authorization process
    if (!scopes.includes('openid')) {
      scopes.push('openid');
    }

    try {
      const { idToken, expiresIn, ...rest } = await httpApi.exchangeUserToken({
        clientId: this.orgId,
        clientSecret: this.authSecret,
        scope: scopes.join(' '),
        codeVerifier,
        code,
        redirectUri
      });

      const clientCallback = new URL(clientRedirectUrl);
      const newParams = new URLSearchParams();
      newParams.append('state', state);
      newParams.append('idToken', idToken);
      newParams.append('expiresIn', expiresIn);

      clientCallback.hash = newParams.toString();

      const clientCallbackLocation = clientCallback.toString();

      return { ...rest, state, idToken, expiresIn, clientCallbackLocation };
    } catch (err) {
      log(err, 'error');
      return Promise.reject(err);
    }
  }

  async pushMessages({ messages, boxTitle, dataSubject, dataTag }) {
    assertNotAnyNil({ messages, boxTitle, dataSubject, dataTag });
    
    if (!isArray(messages)) {
      throw Error('messages must be an array');
    }

    if (!this.accessToken) {
      this.accessToken = await httpApi.exchangeOrgToken(this.orgId, this.authSecret);
    }

    const { publicKey, provision  } = await getPublicKey(
      dataSubject,
      this.secrets,
      this.accessToken
    );

    /* creation of the box */

    const {
      boxId,
      datatagId,
      boxPublicKey,
      invitationKeyShare,
    } = await createBox({
      title: boxTitle,
      dataSubject,
      dataTag,
      dataSubjectPublicKey: publicKey,
      provisionPayload: provision ? provision.creationPayload : null,
      orgId: this.orgId,
      accessToken: this.accessToken,
    });

    /* sending messages */

    // We want to upload the messages sequentially,
    // so we're using `await` in a for loop.
    /* eslint-disable no-restricted-syntax, no-await-in-loop */
    for (const message of messages) {
      if (typeof message === 'string') {
        /* text message */

        const encryptedMessageContent = encryptText(message, boxPublicKey);

        await httpApi.postTextMessage({
          encryptedMessageContent,
          boxId,
          boxPublicKey,
          accessToken: this.accessToken,
        });
      } else {
        /* file message */

        const { data, filename } = message;

        const fileType = mime.lookup(filename);
        const fileSize = data.length;
        const {
          encryptedFile,
          encryptedMessageContent,
        } = await encryptFile(data, boxPublicKey, filename, fileType, fileSize);

        await httpApi.postFileMessage(
          encryptedFile,
          filename,
          encryptedMessageContent,
          boxId,
          boxPublicKey,
          this.accessToken,
        );
      }
    }
    /* eslint-enable no-restricted-syntax, no-await-in-loop */

    const invitationFragment = isEmpty(provision)
      ? invitationKeyShare
      : `provision:${provision.userKeyShare}`;
    const invitationLink = (
      `https://app.${httpApi.BASE_TARGET_DOMAIN}/boxes/${boxId}#${invitationFragment}`
    );

    return {
      boxId,
      datatagId,
      invitationLink,
      dataSubjectNeedsLink: !isEmpty(provision)
    };
  }
}

module.exports = MisakeyServer;
