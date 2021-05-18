const mime = require('mime-types');

const { default: isArray } = require('@misakey/core/helpers/isArray');
const { default: isEmpty } = require('@misakey/core/helpers/isEmpty');
const { default: assertNotAnyNil } = require('@misakey/core/crypto/helpers/assertNotAnyNil');

const { createCryptoForNewBox } = require('@misakey/core/crypto/box/creation');
const { default: encryptText } = require('@misakey/core/crypto/box/encryptText');
const { default: encryptFile } = require('@misakey/core/crypto/box/encryptFile');
const { encryptCryptoaction, decryptCryptoaction } = require('@misakey/core/crypto/cryptoactions');
const { generateAsymmetricKeyPair, keyPairFromSecretKey } = require('@misakey/core/crypto/crypto');
const { splitKey } = require('@misakey/core/crypto/crypto/keySplitting');
const { default: isNil } = require('@misakey/core/helpers/isNil');
const { default: validateProperties } = require('@misakey/core/helpers/validateProperties');
const { default: log } = require('@misakey/core/helpers/log');
const { default: decryptText } = require('@misakey/core/crypto/box/decryptText');
const {
  decryptSecretWithRootKey,
} = require('@misakey/core/crypto/secretStorage');

const httpApi = require('../httpApi');

function ensureConsentPublicKey({ existingConsentPublicKey, dataSubjectPublicKey }) {
  if (existingConsentPublicKey) {
    return {
      consentPublicKey: existingConsentPublicKey,
      newConsentKey: null,
    }
  }

  const {
    secretKey: consentSecretKey,
    publicKey: consentPublicKey
  } = generateAsymmetricKeyPair();

  return {
    consentPublicKey,
    newConsentKey: {
      publicKey: consentPublicKey,
      encryptedSecretKey: {
        // this is actually a cryptoaction
        // (the backend will create a cryptoaction for the data subject from this value)
        encrypted: encryptCryptoaction(
          { consentSecretKey },
          dataSubjectPublicKey,
        ),
        encryptionPublicKey: dataSubjectPublicKey,
      }
    }
  }
}

async function createBox({
  title, dataSubject, datatagId,
  dataSubjectPublicKey, provisionPayload, existingConsentPublicKey,
  orgId, accessToken,
}) {
  const {
    boxPublicKey,
    boxSecretKey,
    invitationKeyShare,
    misakeyKeyShare,
  } = createCryptoForNewBox();

  const { consentPublicKey, newConsentKey } = ensureConsentPublicKey({ existingConsentPublicKey, dataSubjectPublicKey });

  const consentEncryptedSecretKey = {
    // this is the same exact format as a cryptoaction
    // but this value is not distributed through the cryptoaction mechanism in the backend
    // so we don't use `encryptCryptoaction` because this would be confusing
    encrypted: encryptText(
      JSON.stringify({ boxSecretKey }),
      consentPublicKey,
    ),
    encryptionPublicKey: consentPublicKey,
  }

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
    title,
    dataSubject,
    datatagId,
    publicKey: boxPublicKey,
    consentEncryptedSecretKey,
    keyShare: misakeyKeyShare,
    invitationData,
    provisions,
    newConsentKey,
    accessToken,
  });

  return {
    boxId: box.id,
    datatagId,
    boxPublicKey,
    invitationKeyShare,
  };
}

async function loadSecretStorage(accountRootKey, accessToken) {
  const encryptedSecretStorage = await httpApi.getSecretStorage(accessToken);

  // TODO make and use a function `decryptAsymKeysWithRootKey` in core
  // (extract from decryptSecretStorageWithRootKey)
  return {
    asymKeys: (
      Object.fromEntries(Object.entries(encryptedSecretStorage.asymKeys).map(([publicKey, obj]) => {
        const secretKey = decryptSecretWithRootKey(obj.encryptedSecretKey, accountRootKey)
        return [publicKey, secretKey];
      }))
    ),
  }
}

async function loadConsentKeysFromCryptoActions(accountId, currentAsymKeys, accessToken) {
  const cryptoActions = await httpApi.getCryptoActions(accountId, accessToken);

  const newAsymKeys = {};
  cryptoActions.forEach((cryptoAction) => {
    const { type, encrypted, encryptionPublicKey } = cryptoAction;

    if (type !== 'consent_key') {
      return;
    }

    const secretKey = currentAsymKeys[encryptionPublicKey];
    if (isEmpty(secretKey)) {
      throw new Error(`no secret key for public key ${encryptionPublicKey}`)
    }

    const { consentSecretKey } = decryptCryptoaction(encrypted, secretKey);
    const { publicKey } = keyPairFromSecretKey(consentSecretKey);

    newAsymKeys[publicKey] = consentSecretKey;
  });

  return newAsymKeys;
}

async function getPublicKey(identityPubkey, cryptoProvisions, secrets) {
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
  constructor(orgId, authSecret, cryptoSecret) {
    const err = validateProperties({ orgId, authSecret, cryptoSecret });
    if (err) { throw err; }

    this.orgId = orgId;
    this.authSecret = authSecret;
    this.accessToken = null;
    this.cryptoSecret = cryptoSecret;
    this.secrets = {
      // mapping from public key to user key share
      provisionsUserKeyShares: {},
    };
  }

  async exchangeUserToken(params, { client: clientRedirectUrl, server: redirectUri } = {}) {
    const paramsError = validateProperties({ params, redirectUri });
    if (paramsError) { return Promise.reject(paramsError); }

    const { error, errorDebug, errorHint, error_description, code, state, codeVerifier, scope } = params;

    if (!isNil(error)) {
      const description = isNil(errorDebug) ? (isNil(error_description) ? errorHint : error_description) : errorDebug;
      throw new Error(`${error} - ${description}`);
    }

    const err = validateProperties({ state, code });
    if (err) { return Promise.reject(err); }

    try {
      const { idToken, expiresIn, ...rest } = await httpApi.exchangeUserToken({
        clientId: this.orgId,
        clientSecret: this.authSecret,
        scope,
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

    const {
        datatagId,
        cryptoProvisions,
        identityPubkey,
        consentPublicKey: existingConsentPublicKey,
    } = await httpApi.getDataTagCrypto(dataTag, dataSubject, this.accessToken);

    const { publicKey, provision  } = await getPublicKey(
      identityPubkey,
      cryptoProvisions,
      this.secrets,
    );

    /* creation of the box */

    const {
      boxId,
      boxPublicKey,
      invitationKeyShare,
    } = await createBox({
      title: boxTitle,
      dataSubject,
      datatagId,
      dataSubjectPublicKey: publicKey,
      provisionPayload: provision ? provision.creationPayload : null,
      existingConsentPublicKey,
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

  async getData(dataSubject, datatag, producerOrgId) {
    // TODO better parallelism
    const secretStorage = await loadSecretStorage(this.cryptoSecret, this.accessToken);
    console.log({ secretStorage });
    const { accountId } = await httpApi.getIdentity(this.orgId, this.accessToken);
    const asymKeysMapping = await loadConsentKeysFromCryptoActions(accountId, secretStorage.asymKeys, this.accessToken);
    console.log({ asymKeysMapping });

    const {
      datatagId
    } = await httpApi.getDataTagCrypto(datatag, dataSubject, this.accessToken)

    const boxes = await httpApi.listBoxes(dataSubject, datatagId, producerOrgId, this.accessToken);

    // decrypting box secret keys
    boxes.forEach((box) => {
      const {
        consentEncryptedSecretKey: {
          encryptionPublicKey,
          encrypted,
        },
        publicKey,
      } = box;

      const secretKey = asymKeysMapping[encryptionPublicKey];
      if (isEmpty(secretKey)) {
        throw new Error(`no secret key for public key ${encryptionPublicKey}`)
      }

      const { boxSecretKey } = JSON.parse(decryptText(encrypted, secretKey));

      // we already have the box public key, this is just a check
      const { publicKey: rebuiltPublicKey } = keyPairFromSecretKey(boxSecretKey);
      if (rebuiltPublicKey !== publicKey) {
        throw new Error(`rebuilt public key (${rebuiltPublicKey}) different from "official" box public key (${publicKey})`)
      }

      asymKeysMapping[publicKey] = boxSecretKey;
    })

    console.log({ boxes });
    console.log({ asymKeysMapping });

    // TODO decrypt box content using box secret keys
  }
}

module.exports = {
  MisakeyServer,
  // exported because Mijaspy needs it
  loadConsentKeysFromCryptoActions,
};