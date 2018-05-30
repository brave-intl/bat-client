const Ledger = require('../index.js')
const crypto = require('brave-crypto')
const test = require('tape')

const options = { debugP: true, version: 'v2' }

const msecs = {
  day: 24 * 60 * 60 * 1000,
  hour: 60 * 60 * 1000,
  minute: 60 * 1000,
  second: 1000
}

/**
 * assert that values v1 and v2 differ by no more than tol
 **/
const assertWithinBounds = (t, v1, v2, tol, msg) => {
  if (v1 > v2) {
    t.true((v1 - v2) <= tol, msg)
  } else {
    t.true((v2 - v1) <= tol, msg)
  }
}

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

test('sync', (t) => {
  t.plan(3)
  let client = new Ledger(null, options)
  const days14 = 1209600000

  t.equal(client.state.reconcileStamp, undefined, 'Should be undefined at start')

  client.sync(() => {})

  const now = new Date().getTime()
  const newStamp = now + days14

  assertWithinBounds(t, client.state.reconcileStamp, newStamp, 1000, 'Should set new reconcileStamp')
  console.log(client.state.reconcileStamp)

  client = new Ledger(null, options)
  client.setTimeUntilReconcile(null, () => {})
  const time = client.state.reconcileStamp
  client.sync(() => {})
  t.equal(client.state.reconcileStamp, time, 'Should not change timestamp if is set')
})

test('setTimeUntilReconcile', (t) => {
  t.plan(3)

  const client = new Ledger(null, options)
  const newTimestamp = new Date().getTime() + 10000000
  const now = new Date().getTime() + 2592000000

  t.equal(client.state.reconcileStamp, undefined, 'Should be undefined at start')

  client.setTimeUntilReconcile(newTimestamp, () => {})
  t.equal(client.state.reconcileStamp, newTimestamp, 'Should set provided timestamp')

  client.setTimeUntilReconcile(null, () => {})
  assertWithinBounds(t, client.state.reconcileStamp, now, 1000, 'Should set new timestamp to now + 30 days')
})

test('_fuzzing', (t) => {
  t.plan(8)
  const client = new Ledger(null, options, {properties: {days: 30}})

  const synopsis = {
    prune: () => {},
    publishers: {
      'site.com': {
        duration: 10
      }
    },
    options: {
      numFrames: 30,
      frameSize: 86400000
    }
  }

  const synopsisTime = {
    prune: () => {},
    publishers: {
      'site.com': {
        duration: 31 * msecs.minute
      }
    },
    options: {
      numFrames: 30,
      frameSize: 86400000
    }
  }
  t.equal(client.state.reconcileStamp, undefined, 'Should be undefined at start')

  const fiveDays = new Date().getTime() + (5 * msecs.day)
  client.setTimeUntilReconcile(fiveDays, () => {})
  t.equal(client.state.reconcileStamp, fiveDays, 'Should set time now+5days stamp')
  client._fuzzing(synopsis, () => {})
  t.equal(client.state.reconcileStamp, fiveDays, 'Should not be changed if stamp is in the near future (5days)')

  const tomorrow = new Date().getTime() + (1 * msecs.day)
  client.setTimeUntilReconcile(tomorrow, () => {})
  t.equal(client.state.reconcileStamp, tomorrow, 'Should set time now+1day stamp')
  client._fuzzing(synopsis, () => {})
  assertWithinBounds(t, client.state.reconcileStamp, (new Date().getTime() + (5 * msecs.day)), 1000, 'Should be changed if stamp is tomorrow and browsing time is bellow 30min')

  const past = new Date().getTime() - (5 * msecs.day)
  const pastClient = new Ledger(null, options, {properties: {days: 30}, reconcileStamp: past})
  pastClient._fuzzing(synopsis, () => {})
  assertWithinBounds(t, pastClient.state.reconcileStamp, new Date().getTime() + (5 * msecs.day), 1000, 'Should be changed if stamp is in the past and browsing time is bellow 30min')

  client.setTimeUntilReconcile(tomorrow, () => {})
  t.equal(client.state.reconcileStamp, tomorrow, 'Should set time now+1day stamp')
  client._fuzzing(synopsisTime, () => {})
  t.equal(client.state.reconcileStamp, tomorrow, 'Should not change if stamp is in tomorrow and browsing time is above 30min')
})

test('_prepareVoteBatch', (t) => {
  t.plan(8)
  const client = new Ledger(null, options)
  const callback = () => {}

  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {}, 'Should be empty for null case')

  client.state = {
    batch: {},
    ballots: null
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {}, 'Should be empty when we do not have ballots')

  client.state = {
    batch: {},
    ballots: null
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {}, 'Should be empty for null case')

  client.state = {
    batch: {},
    ballots: [{
      surveyorId: '12323',
      publisher: 'clifton.io',
      viewingId: '123a',
      prepareBallot: {
        surveyorId: '12323'
      },
      proofBallot: 'dfdsfsd'
    }],
    transactions: []
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {}, 'Should be empty when there is no transaction')

  client.state = {
    batch: {},
    ballots: [{
      publisher: 'clifton.io',
      viewingId: '123a'
    }],
    transactions: [{
      viewingId: '123a',
      credential: '12'
    }]
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {}, 'Should be empty when ballot is missing proof and prepare')

  client.state = {
    batch: {},
    ballots: [{
      surveyorId: '12323',
      publisher: 'clifton.io',
      viewingId: '123a',
      prepareBallot: {
        surveyorId: '12323'
      },
      proofBallot: 'dfdsfsd'
    }],
    transactions: [{
      viewingId: '123a',
      credential: '12'
    }]
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, {
    'clifton.io': [{
      surveyorId: '12323',
      proof: 'dfdsfsd'
    }]
  }, 'Should have one batch')
  t.deepEqual(client.state.ballots, [], 'Should not have any ballots when we move it into the batch')

  client.state = {
    batch: {},
    ballots: [
      {
        surveyorId: '1',
        publisher: 'clifton.io',
        viewingId: '123a',
        prepareBallot: {
          surveyorId: '1'
        },
        proofBallot: '2'
      },
      {
        surveyorId: '2',
        publisher: 'clifton.io',
        viewingId: '123a',
        prepareBallot: {
          surveyorId: '2'
        },
        proofBallot: '3'
      },
      {
        surveyorId: '3',
        publisher: 'clifton.io',
        viewingId: '123a',
        prepareBallot: {
          surveyorId: '3'
        },
        proofBallot: '4'
      },
      {
        surveyorId: '4',
        publisher: 'brianbondy.com',
        viewingId: '123a',
        prepareBallot: {
          surveyorId: '4'
        },
        proofBallot: '1'
      },
      {
        surveyorId: '5',
        publisher: 'brianbondy.com',
        viewingId: '123a',
        prepareBallot: {
          surveyorId: '5'
        },
        proofBallot: '2'
      }],
    transactions: [{
      viewingId: '123a',
      credential: '12'
    }]
  }
  const expectedResult = {
    'brianbondy.com': [
      {
        surveyorId: '5',
        proof: '2'
      },
      {
        surveyorId: '4',
        proof: '1'
      }
    ],
    'clifton.io': [
      {
        surveyorId: '3',
        proof: '4'
      },
      {
        surveyorId: '2',
        proof: '3'
      },
      {
        surveyorId: '1',
        proof: '2'
      }
    ]
  }
  client._prepareVoteBatch(callback)
  t.deepEqual(client.state.batch, expectedResult, 'Should have multiple publishers in the batch')
})
