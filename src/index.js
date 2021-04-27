const mime = require('mime-types');

const { default: isArray } = require('@misakey/core/helpers/isArray');
const { default: isEmpty } = require('@misakey/core/helpers/isEmpty');
const { default: assertNotAnyNil } = require('@misakey/core/crypto/helpers/assertNotAnyNil')

const { createCryptoForNewBox } = require('@misakey/core/crypto/box/creation');
const { default: encryptText } = require('@misakey/core/crypto/box/encryptText');
const { default: encryptFile } = require('@misakey/core/crypto/box/encryptFile');
const { encryptCryptoaction } = require('@misakey/core/crypto/cryptoactions');
const { generateAsymmetricKeyPair } = require('@misakey/core/crypto/crypto');
const { splitKey } = require('@misakey/core/crypto/crypto/keySplitting');

const httpApi = require('./httpApi');

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
    }
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

class Misakey {
  constructor(orgId, authSecret) {
    this.orgId = orgId;
    this.authSecret = authSecret;
    this.accessToken = null;
    this.secrets = {
      // mapping from public key to user key share
      provisionsUserKeyShares: {},
    }
  }

  async pushMessages({ messages, boxTitle, dataSubject, dataTag }) {
    assertNotAnyNil({ messages, boxTitle, dataSubject, dataTag });
    
    if (!isArray(messages)) {
      throw Error('messages must be an array');
    }

    if (!this.accessToken) {
      this.accessToken = await httpApi.exchangeToken(this.orgId, this.authSecret);
    }

    /*
     * public key to send the auto-inviation to
     * (potentially of a provision, which we may have to create)
    */

    const {
      cryptoProvisions,
      identityPubkey,
    } = await httpApi.getIdentifierPublicKey(dataSubject, this.accessToken);

    let publicKey;
    let provision = {};
    if (identityPubkey) {
      publicKey = identityPubkey;
    } else if (!isEmpty(cryptoProvisions)) {
      publicKey = cryptoProvisions[0].publicKey;

      const userKeyShare =  this.secrets.provisionsUserKeyShares[publicKey];
      if (!userKeyShare) {
        // TODO maybe create a new provision instead,
        // or try the other provision public keys if any
        throw Error(`could not find user key share for provision public key ${publicKey} in memory`);
      }

      provision = {
        userKeyShare,
      }
    } else {
      provision = createNewProvisionMaterial();
      this.secrets.provisionsUserKeyShares[provision.publicKey] = provision.userKeyShare;
      publicKey = provision.publicKey;
    }

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
      provisionPayload: provision.creationPayload,
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
    )

    return {
      boxId,
      datatagId,
      invitationLink,
      dataSubjectNeedsLink: !isEmpty(provision)
    };
  }
}

module.exports = Misakey;
