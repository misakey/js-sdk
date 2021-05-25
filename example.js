const fs = require('fs');

const Misakey = require('./src');

/* eslint-disable import/no-unresolved */
/*
 * create a file `example-variables.js`
 * and make it export these variables
 * with the values you want.
 */
const {
  ORG_ID,
  ORG_AUTH_SECRET,
  ORG_CRYPTO_SECRET,
  BOXES,
  DATA_SUBJECT,
} = require('./example-variables');
/* eslint-enable import/no-unresolved */

Object.entries({
  ORG_ID,
  ORG_AUTH_SECRET,
  ORG_CRYPTO_SECRET, 
  BOXES,
  DATA_SUBJECT,
}).forEach(([name, value]) => {
  if (!value) {
    throw Error(`missing variable ${name}`);
  }
});

if (!process.env.MISAKEY_SDK_BASE_TARGET_DOMAIN) {
  throw Error('`env variable MISAKEY_SDK_BASE_TARGET_DOMAIN not set');
}

async function main(misakey, box) {
  const { title, dataTag, messages } = box;

  const preparedMessages = messages.map((message) => {
    if (typeof(message) === 'string') {
      return message;
    }

    const { pathToFile } = message;

    if (!pathToFile) {
      throw Error(`message is neither string nor object with "pathToFile" property: ${message}`);
    }

    return {
      filename: pathToFile.split('/').pop(-1),
      data: fs.readFileSync(pathToFile),
    }
  });

  const boxInfo = await misakey.pushMessages({
    messages: preparedMessages,
    boxTitle: title,
    dataSubject: DATA_SUBJECT,
    dataTag,
  });  

  return {
    misakey,
    boxInfo,
  };
}

/* eslint-disable no-console */
if (require.main === module) {
  (async () => {
    try {
      const misakey = new Misakey(ORG_ID, ORG_AUTH_SECRET, ORG_CRYPTO_SECRET);
      for (const box of BOXES) {
        const { boxInfo } = await main(misakey, box);
        console.log(boxInfo);
      }
    } catch (error) {
      try {
        const jsonBody = await error.response.json();
        console.error('ERROR:', jsonBody);
      } catch {
        console.error('ERROR:', error);
      }
      console.log(error.stack);
    }
  })();
}
/* eslint-enable no-console */
