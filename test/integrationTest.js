const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2', environment: 'staging' }

test('fetchPublisherInfo', async (t) => {
  t.plan(3)

  // Use staging endpoint
  const fetchOptions = {
    debugP: true,
    version: 'v2',
    environment: 'staging',
    server: 'https://publishers-staging.basicattentiontoken.org'
  }

  const client = new Ledger(null, fetchOptions)
  client.sync(function () {
    client.fetchPublisherInfo(function (err, result) {
      t.false(err)
      t.true(Array.isArray(result))
      t.equal(result[0].length, 3)
    })
  })
})

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

test('balance', async (t) => {
  t.plan(2)
  const client = new Ledger(null, options)

  client.sync(function () {
    client.getWalletProperties(function (err, resp) {
      t.false(err)
      t.equal(resp.probi, '0')
    })
  })
})

test('promotion', async (t) => {
  t.plan(7)

  const client = {
    sync: (callback) => {
      callback()
    },
    getPromotion: (lang, forPaymentId, callback) => {
      const resp = {
        promotionId: '5787de72e-174d-4fb3-bdf6-2e70b2b0ac86'
      }
      callback(null, resp)
    },
    setPromotion: (promotionId, callback) => {
      const resp = {
        probi: '10000000000000000000'
      }
      callback(null, resp)
    },
    getWalletProperties: (callback) => {
      const resp = {
        probi: '10000000000000000000'
      }
      callback(null, resp)
    },
    getPaymentId: () => {}
  }

  const client2 = {
    getPromotion: (lang, paymentId, callback) => {
      const err = {
        message: '404'
      }
      callback(err)
    }
  }

  client.sync(function () {
    client.getPromotion(null, null, function (err, resp) {
      t.false(err)
      t.true(resp.hasOwnProperty('promotionId'))
      const promotionId = resp.promotionId
      client.setPromotion(promotionId, function (err, resp) {
        t.false(err)
        t.true(resp.hasOwnProperty('probi'))
        const grantProbi = resp.probi
        client.getWalletProperties(function (err, resp) {
          t.false(err)
          t.equal(resp.probi, grantProbi)
          client2.getPromotion(null, client.getPaymentId(), function (err, resp) {
            t.true(err)
          })
        })
      })
    })
  })
})
