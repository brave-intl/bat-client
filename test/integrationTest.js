const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2' }

test('recoverWallet', async (t) => {
  t.plan(6)
  const client = new Ledger(null, options)

  client.sync(function () {
    const signingKey = client.getKeypair()
    const passPhrase = client.getWalletPassphrase()
    const addresses = client.getWalletAddresses()

    const client2 = new Ledger(null, options)
    client2.sync(function () {
      const signingKey2 = client2.getKeypair()
      const addresses2 = client2.getWalletAddresses()

      t.notEqual(crypto.uint8ToHex(signingKey.secretKey), crypto.uint8ToHex(signingKey2.secretKey))
      t.notEqual(crypto.uint8ToHex(signingKey.publicKey), crypto.uint8ToHex(signingKey2.publicKey))
      t.notDeepEqual(addresses, addresses2)

      client2.recoverWallet(null, passPhrase.join(' '), function () {
        const signingKey3 = client2.getKeypair()
        const addresses3 = client2.getWalletAddresses()

        t.equal(crypto.uint8ToHex(signingKey.secretKey), crypto.uint8ToHex(signingKey3.secretKey))
        t.equal(crypto.uint8ToHex(signingKey.publicKey), crypto.uint8ToHex(signingKey3.publicKey))
        t.deepEqual(addresses, addresses3)
      })
    })
  })
})
