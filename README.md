# The Misakey SDK

A NodeJS package that lets you send text messages and files to users through Misakey.

```javascript
const fs = require('fs');
const Misakey = require('@misakey/sdk');

const misakey = new Misakey(YOUR_ORG_ID, YOUR_ORG_AUTH_SECRET);
misakey.pushMessages({
  messages: [
    `Hello ${DATA_SUBJECT}, here is your data :-)`,
    {
      filename: PATH_TO_FILE.split('/').pop(-1),
      data: fs.readFileSync(PATH_TO_FILE),
    },
  ],
  boxTitle: `Your ${DATATAG} data`,
  dataSubject: DATA_SUBJECT,
  dataTag: DATATAG,
}).then((boxInfo) => console.log(boxInfo));
```

Output:

```
{
  boxId: 'd8dcbd74-a50e-42fb-a25d-1618f07da4f4',
  datatagId: '35aec043-bb95-4c93-8d1b-e311021baba1',
  invitationLink: 'https://app.misakey.com/boxes/d8dcbd74-a50e-42fb-a25d-1618f07da4f4#h_iSvbUr_3wnNQ6SK6-p6hS2U9xXbuzFYewxJz2jIwY',
  dataSubjectNeedsLink: true
}
```

If you want to point to a different base domain that `misakey.com`
(typically, to point to a test/demo domain)
you can do so by setting environment variable `MISAKEY_SDK_BASE_TARGET_DOMAIN`.


See also example file `example.js`.
Note that it *requires* `MISAKEY_SDK_BASE_TARGET_DOMAIN` to be set,
so that you don't unintentionally call `misakey.com` while tinkering with the SDK.
It also requires you to create a file `example-variables.js`
that exports the variables it needs:

```javascript
// file: example-variables.js
module.exports = {
  ORG_ID: 'c83c496f-b801-465c-a678-4616fa9fd36f',
  ORG_AUTH_SECRET: 'nDUJ4hIYsbrfFJ0QBkQUWQB8/giwapLHAqJ6IQpgd0Y=',
  DATA_SUBJECT: 'michel@misakey.com',
  BOXES: [
    {
      title: 'Your Contract',
      dataTag: 'contract',
      messages: [
        'Please find below your contract:',
        {
          pathToFile: '/var/data/contracts/michel-at-misakey-dot-com.pdf',
        },
        'Thank you for choosing us.',
      ]
    },
    {
      title: 'Your order',
      dataTag: 'purchase',
      messages: [
        'Hi, please find below your receipt and other related documents',
        {
          pathToFile: '/var/data/purchases/1D6FC90D5/receipt.pdf',
        },
        {
          pathToFile: '/var/data/purchases/1D6FC90D5/infalatable-unicorn-user-manual.pdf',
        },
        'Thanks for shopping with us ☺.',
      ]
    }
  ],
};
```

```
$ MISAKEY_SDK_BASE_TARGET_DOMAIN=misakey.com.local node example.js
{
  boxId: '89defdad-d913-4bfa-8648-41328748188f',
  datatagId: '35aec043-bb95-4c93-8d1b-e311021baba1',
  invitationLink: 'https://app.misakey.com.local/boxes/89defdad-d913-4bfa-8648-41328748188f#j_NzjPZd6iDGE5uXzGlvuMS1EeSkMHYuOMRtFXSFZHU',
  dataSubjectNeedsLink: true
}
```