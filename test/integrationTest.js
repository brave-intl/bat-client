const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2', environment: 'staging' }

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

test('transition', async (t) => {
  t.plan(3)
  const oldOptions = { debugP: true, version: 'v1', environment: 'staging' }
  const client = new Ledger(null, oldOptions)

  client.sync(function () {
    const newClient = new Ledger(null, options)
    newClient.sync(function () {
      const newPaymentId = newClient.getPaymentId()

      client.transition(newPaymentId, function (err, properties) {
        t.false(err)
        t.true(properties)
        t.true(properties.reconcileStamp)
      })
    })
  })
})
