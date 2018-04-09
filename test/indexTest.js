const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2' }

test('getWalletPassphrase', (t) => {
  t.plan(2)
  const client = new Ledger(null, options)

  client.generateKeypair()

  const bip39PassPhrase = client.getWalletPassphrase()
  t.equal(bip39PassPhrase.length, 24, 'bip39 passphrase should be 24 words')

  const nicewarePassPhrase = client.getWalletPassphrase(undefined, {useNiceware: true})
  t.equal(nicewarePassPhrase.length, 16, 'niceware passphrase should be 16 words')
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
  t.plan(4)

  const client = new Ledger(null, options)

  // test with bip39 passphrase
  const signingKey = client.generateKeypair()
  const bip39PassPhrase = client.getWalletPassphrase().join(' ')

  const client2 = new Ledger(null, options)
  t.equal(crypto.uint8ToHex(client2.recoverKeypair(bip39PassPhrase).secretKey), crypto.uint8ToHex(signingKey.secretKey))
  t.equal(crypto.uint8ToHex(client2.recoverKeypair(bip39PassPhrase).publicKey), crypto.uint8ToHex(signingKey.publicKey))

  // test with niceware passphrase
  const nicewarePassPhrase = client.getWalletPassphrase(undefined, {useNiceware: true}).join(' ')

  const client3 = new Ledger(null, options)
  t.equal(crypto.uint8ToHex(client3.recoverKeypair(nicewarePassPhrase).secretKey), crypto.uint8ToHex(signingKey.secretKey))
  t.equal(crypto.uint8ToHex(client3.recoverKeypair(nicewarePassPhrase).publicKey), crypto.uint8ToHex(signingKey.publicKey))
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

test('isValidPassPhrase', (t) => {
  t.plan(6)

  const client = new Ledger(null, options)

  client.generateKeypair()
  const bip39PassPhrase = client.getWalletPassphrase().join(' ')
  t.equal(client.isValidPassPhrase(bip39PassPhrase), true, 'Should return true for valid passphrase')
  t.equal(client.isValidPassPhrase(123), false, 'Should return false for number')
  t.equal(client.isValidPassPhrase(null), false, 'Should return false for null')
  t.equal(client.isValidPassPhrase(), false, 'Should return false for empty param')
  t.equal(client.isValidPassPhrase('asdfasfsadf'), false, 'Should return false for random string')

  const nicewarePassPhrase = client.getWalletPassphrase(undefined, {useNiceware: true}).join(' ')
  t.equal(client.isValidPassPhrase(nicewarePassPhrase), true, 'Should return true for legacy niceware passphrase')
})
