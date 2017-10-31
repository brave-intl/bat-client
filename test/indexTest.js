const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2' }

test('getWalletPassphrase', (t) => {
  t.plan(1)
  const client = new Ledger(null, options)

  client.generateKeypair()

  const passPhrase = client.getWalletPassphrase()
  t.equal(passPhrase.length, 16)
})

test('getKeypair', (t) => {
  t.plan(2)

  const client = new Ledger(null, options)

  const signingKey = client.generateKeypair()
  const signingKey2 = client.getKeypair()

  t.equal(crypto.uint8ToHex(signingKey.secretKey), crypto.uint8ToHex(signingKey2.secretKey))
  t.equal(crypto.uint8ToHex(signingKey.publicKey), crypto.uint8ToHex(signingKey2.publicKey))
})

test('recoverKeypair', (t) => {
  t.plan(2)

  const client = new Ledger(null, options)

  const signingKey = client.generateKeypair()
  const passPhrase = client.getWalletPassphrase().join(' ')

  const client2 = new Ledger(null, options)
  t.equal(crypto.uint8ToHex(client2.recoverKeypair(passPhrase).secretKey), crypto.uint8ToHex(signingKey.secretKey))
  t.equal(crypto.uint8ToHex(client2.recoverKeypair(passPhrase).publicKey), crypto.uint8ToHex(signingKey.publicKey))
})

// Tests workaround for #20
test('initWithDeserializedState', (t) => {
  t.plan(2)

  const client = new Ledger(null, options)

  const signingKey = client.generateKeypair()
  const state = JSON.parse(JSON.stringify(client.state))

  const client2 = new Ledger(null, options, state)
  const signingKey2 = client2.getKeypair()

  t.equal(crypto.uint8ToHex(signingKey.secretKey), crypto.uint8ToHex(signingKey2.secretKey))
  t.equal(crypto.uint8ToHex(signingKey.publicKey), crypto.uint8ToHex(signingKey2.publicKey))
})

test('initWithFixupState', (t) => {
  t.plan(2)

  const client = new Ledger(null, options)

  const signingKey = client.generateKeypair()
  const state = JSON.parse(JSON.stringify(client.state))

  if (state && state.properties && state.properties.wallet && state.properties.wallet.keyinfo) {
    let seed = state.properties.wallet.keyinfo.seed
    if (!(seed instanceof Uint8Array)) {
      seed = new Uint8Array(Object.values(seed))
    }

    state.properties.wallet.keyinfo.seed = seed
  }

  const client2 = new Ledger(null, options, state)
  const signingKey2 = client2.getKeypair()

  t.equal(crypto.uint8ToHex(signingKey.secretKey), crypto.uint8ToHex(signingKey2.secretKey))
  t.equal(crypto.uint8ToHex(signingKey.publicKey), crypto.uint8ToHex(signingKey2.publicKey))
})
