const crypto = require('crypto')
const http = require('http')
const https = require('https')
const path = require('path')
const querystring = require('querystring')
const url = require('url')
const braveCrypto = require('brave-crypto')
const passphraseUtil = braveCrypto.passphrase

const anonize = require('node-anonize2-relic-emscripten')
const backoff = require('@ambassify/backoff-strategies')
const balance = require('bat-balance')
const Joi = require('joi')
const random = require('random-lib')
const { sign } = require('http-request-signature')
const stringify = require('json-stable-stringify')
const underscore = require('underscore')
const uuid = require('uuid')

const batPublisher = require('bat-publisher')

const SEED_LENGTH = 32
const HKDF_SALT = new Uint8Array([ 126, 244, 99, 158, 51, 68, 253, 80, 133, 183, 51, 180, 77, 62, 74, 252, 62, 106, 96, 125, 241, 110, 134, 87, 190, 208, 158, 84, 125, 69, 246, 207, 162, 247, 107, 172, 37, 34, 53, 246, 105, 20, 215, 5, 248, 154, 179, 191, 46, 17, 6, 72, 210, 91, 10, 169, 145, 248, 22, 147, 117, 24, 105, 12 ])
const LEDGER_SERVERS = {
  'staging': {
    v1: 'https://ledger-staging.brave.com',
    v2: 'https://ledger-staging.mercury.basicattentiontoken.org'
  },
  'production': {
    v1: 'https://ledger.brave.com',
    v2: 'https://ledger.mercury.basicattentiontoken.org'
  }
}

const Client = function (personaId, options, state) {
  if (!(this instanceof Client)) return new Client(personaId, options, state)

  const self = this

  const now = underscore.now()
  const later = now + (15 * msecs.minute)

  self.options = underscore.defaults(underscore.clone(options || {}),
                                     { version: 'v1', debugP: false, loggingP: false, verboseP: false })

  const env = self.options.environment || 'production'
  const version = self.options.version || 'v2'
  underscore.defaults(self.options,
    { server: LEDGER_SERVERS[env][version],
      prefix: '/' + self.options.version
    })
  underscore.keys(self.options).forEach(function (option) {
    if ((option.lastIndexOf('P') + 1) === option.length) self.options[option] = Client.prototype.boolion(self.options[option])
  })
  if (typeof self.options.server === 'string') {
    self.options.server = url.parse(self.options.server)
    if (!self.options.server) throw new Error('invalid options.server')
  }

  if (typeof self.options.roundtrip !== 'undefined') {
    if (typeof self.options.roundtrip !== 'function') throw new Error('invalid roundtrip option (must be a function)')

    self._innerTrip = self.options.roundtrip.bind(self)
    self.roundtrip = function (params, callback) { self._innerTrip(params, self.options, callback) }
  } else if (self.options.debugP) self.roundtrip = self._roundTrip
  else throw new Error('security audit requires options.roundtrip for non-debug use')
  self._retryTrip = self._retryTrip.bind(self)
  if (self.options.debugP) console.log(JSON.stringify(self.options, null, 2))

  // Workaround #20
  if (state && state.properties && state.properties.wallet && state.properties.wallet.keyinfo) {
    let seed = state.properties.wallet.keyinfo.seed
    if (!(seed instanceof Uint8Array)) {
      seed = new Uint8Array(Object.values(seed))
    }

    state.properties.wallet.keyinfo.seed = seed
  }
  self.state = underscore.defaults(state || {}, { personaId: personaId, options: self.options, ballots: [], transactions: [] })
  self.logging = []

  if (self.options.rulesTestP) {
    self.state.updatesStamp = now - 1
    if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)
  }
  if ((self.state.updatesStamp) && (self.state.updatesStamp > later)) {
    self.state.updatesStamp = later
    if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)
  }

  if (self.state.wallet) throw new Error('deprecated state (alpha) format')

  this.seqno = 0
  this.callbacks = {}
}

const msecs = {
  day: 24 * 60 * 60 * 1000,
  hour: 60 * 60 * 1000,
  minute: 60 * 1000,
  second: 1000
}

Client.prototype.sync = function (callback) {
  const self = this

  const now = underscore.now()
  let ballot, ballots, i, memo, transaction, updateP

  if (typeof callback !== 'function') throw new Error('sync missing callback parameter')

  if (!self.state.properties) self.state.properties = {}
  if ((self.state.reconcileStamp === null) || (isNaN(self.state.reconcileStamp))) {
    memo = { prevoiusStamp: self.state.reconcileStamp }
    self.state.reconcileStamp = now + (14 * msecs.day)
    memo.reconcileStamp = self.state.reconcileStamp
    memo.reconcileDate = new Date(self.state.reconcileStamp)
    self.memo('sync', memo)

    self._log('sync', { reconcileStamp: self.state.reconcileStamp })
    self.setTimeUntilReconcile(self.state.reconcileStamp)
  }
  // the caller is responsible for checking that the reconcileStamp is too historic...
  if ((self.state.properties.days) && (self.state.reconcileStamp > (now + (self.state.properties.days * msecs.day)))) {
    self._log('sync', { reconcileStamp: self.state.reconcileStamp })
    return self.setTimeUntilReconcile(null, callback)
  }

// begin: legacy updates...
  if (self.state.ruleset) {
    self.state.ruleset.forEach(function (rule) {
      if (rule.consequent) return

      self.state.updatesStamp = now - 1
      if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)
    })
    delete self.state.ruleset
  }
  if (!self.state.ruleset) {
    self.state.ruleset = [
      {
        condition: '/^[a-z][a-z].gov$/.test(SLD)',
        consequent: 'QLD + \'.\' + SLD',
        description: 'governmental sites'
      },
      {
        condition: "TLD === 'gov' || /^go.[a-z][a-z]$/.test(TLD) || /^gov.[a-z][a-z]$/.test(TLD)",
        consequent: 'SLD',
        description: 'governmental sites'
      },
      {
        condition: "SLD === 'keybase.pub'",
        consequent: 'QLD + \'.\' + SLD',
        description: 'keybase users'
      },
      {
        condition: true,
        consequent: 'SLD',
        description: 'the default rule'
      }
    ]
  }
  if (self.state.verifiedPublishers) {
    delete self.state.verifiedPublishers
    self.state.updatesStamp = now - 1
    if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)
  }
// end: legacy updates...

  if ((self.credentials) && (!self.state.rulesV2Stamp)) {
    try {
      const bootstrap = require(path.join(__dirname, 'bootstrap'))

      underscore.extend(self.state, bootstrap)
      return callback(null, self.state, msecs.minute)
    } catch (ex) {}
  }

  if (self.state.updatesStamp < now) {
    return self._updateRules(function (err) {
      if (err) self._log('_updateRules', { message: err.toString() })

      self._log('sync', { delayTime: msecs.minute })
      callback(null, self.state, msecs.minute)
    })
  }

  if (!self.credentials) self.credentials = {}

  if (!self.state.persona) return self._registerPersona(callback)
  self.credentials.persona = new anonize.Credential(self.state.persona)

  if (self.options.verboseP) console.log('+++ busyP=' + self.busyP())

  ballots = underscore.shuffle(self.state.ballots)
  for (i = ballots.length - 1; i >= 0; i--) {
    ballot = ballots[i]
    transaction = underscore.find(self.state.transactions, function (transaction) {
      return ((transaction.credential) &&
              (ballot.viewingId === transaction.viewingId) &&
              ((!ballot.prepareBallot) || (!ballot.delayStamp) || (ballot.delayStamp <= now)))
    })
    if (!transaction) continue

    if (!ballot.prepareBallot) return self._prepareBallot(ballot, transaction, callback)
    return self._commitBallot(ballot, transaction, callback)
  }

  transaction = underscore.find(self.state.transactions, function (transaction) {
    if ((transaction.credential) || (transaction.ballots)) return

    try { return self._registerViewing(transaction.viewingId, callback) } catch (ex) {
      self._log('_registerViewing', { errP: 1, message: ex.toString(), stack: ex.stack })
    }
  })

  if (self.state.currentReconcile) return self._currentReconcile(callback)

  for (i = self.state.transactions.length - 1; i > 0; i--) {
    transaction = self.state.transactions[i]
    ballot = underscore.find(self.state.ballots, function (ballot) { return (ballot.viewingId === transaction.viewingId) })

    if ((transaction.count === transaction.votes) && (!!transaction.credential) && (!ballot)) {
      self.state.transactions[i] = underscore.omit(transaction, [ 'credential', 'surveyorIds', 'err' ])
      updateP = true
    }
  }
  if (updateP) {
    self._log('sync', { delayTime: msecs.minute })
    return callback(null, self.state, msecs.minute)
  }

  self._log('sync', { result: true })
  return true
}

const propertyList = [ 'setting', 'days', 'fee' ]

Client.prototype.getBraveryProperties = function () {
  const errP = !this.state.properties

  this._log('getBraveryProperties', { errP: errP, result: underscore.pick(this.state.properties || {}, propertyList) })
  if (errP) throw new Error('Ledger client initialization incomplete.')

  return underscore.pick(this.state.properties, propertyList)
}

Client.prototype.setBraveryProperties = function (properties, callback) {
  const self = this

  if (typeof callback !== 'function') throw new Error('setBraveryProperties missing callback parameter')

  properties = underscore.pick(properties, propertyList)
  self._log('setBraveryProperties', properties)

  underscore.defaults(self.state.properties, properties)
  callback(null, self.state)
}

Client.prototype.getPaymentId = function () {
  const paymentId = this.state.properties && this.state.properties.wallet && this.state.properties.wallet.paymentId

  this._log('getPaymentId')

  return paymentId
}

Client.prototype.getWalletAddress = function () {
  const wallet = this.state.properties && this.state.properties.wallet

  this._log('getWalletAddress')

  if (!wallet) return

  if ((wallet.addresses) && (wallet.addresses.BAT)) return wallet.addresses.BAT

  return wallet.address
}

Client.prototype.getWalletAddresses = function () {
  const wallet = this.state.properties && this.state.properties.wallet
  let addresses

  this._log('getWalletAddresses')

  if (!wallet) return

  addresses = underscore.extend({}, wallet.addresses)
  if (wallet.address) addresses.BTC = wallet.address
  return addresses
}

Client.prototype.getWalletProperties = function (amount, currency, callback) {
  const self = this

  const prefix = self.options.prefix + '/wallet/'
  let params, errP, path, suffix

  if (typeof amount === 'function') {
    callback = amount
    amount = null
    currency = null
  } else if (typeof currency === 'function') {
    callback = currency
    currency = null
  }

  if (typeof callback !== 'function') throw new Error('getWalletProperties missing callback parameter')

  errP = (!self.state.properties) || (!self.state.properties.wallet)
  self._log('getWalletProperties', { errP: errP })
  if (errP) throw new Error('Ledger client initialization incomplete.')

  if ((!self.state.currentReconcile) && (self.state.reconcileStamp) && (self.state.reconcileStamp > underscore.now())) {
    params = underscore.pick(self.state.properties.wallet, ['addresses', 'paymentId'])
  }
  if (params) {
    balance.getProperties(params, self.options, (err, provider, result) => {
      self._log('getWalletProperties', { method: 'GET', path: 'getProperties', errP: !!err })
      if (err) return callback(err)

      if (!result.addresses) result.addresses = underscore.clone(self.state.properties.wallet.addresses)
      callback(null, result)
    })
    return
  }

  suffix = '?balance=true&' + self._getWalletParams({ amount: amount, currency: currency })
  path = prefix + self.state.properties.wallet.paymentId + suffix
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    self._log('getWalletProperties', { method: 'GET', path: prefix + '...' + suffix, errP: !!err })
    if (err) return callback(err)

    callback(null, body)
  })
}

Client.prototype.setTimeUntilReconcile = function (timestamp, callback) {
  const now = underscore.now()

  if ((!timestamp) || (timestamp < now)) {
    let days = 30
    if (this.state && this.state.properties && this.state.properties.days) {
      days = this.state.properties.days
    }
    timestamp = now + (days * msecs.day)
  }
  this.state.reconcileStamp = timestamp
  if (this.options.verboseP) this.state.reconcileDate = new Date(this.state.reconcileStamp)

  if (callback) {
    callback(null, this.state)
  }
}

Client.prototype.timeUntilReconcile = function (synopsis) {
  if (!this.state.reconcileStamp) {
    this._log('isReadyToReconcile', { errP: true })
    throw new Error('Ledger client initialization incomplete.')
  }

  if (this.state.currentReconcile) {
    this._log('isReadyToReconcile', { reason: 'already reconciling', reconcileStamp: this.state.reconcileStamp })
    return false
  }

  this._fuzzing(synopsis)
  return (this.state.reconcileStamp - underscore.now())
}

Client.prototype.isReadyToReconcile = function (synopsis) {
  const delayTime = this.timeUntilReconcile()

  this._log('isReadyToReconcile', { delayTime: delayTime })
  this._fuzzing(synopsis)
  return ((typeof delayTime === 'boolean') ? delayTime : (delayTime <= 0))
}

Client.prototype.reconcile = function (viewingId, callback) {
  const self = this

  const prefix = self.options.prefix + '/surveyor/contribution/current/'
  let delayTime, path, schema, validity

  if (!callback) {
    callback = viewingId
    viewingId = null
  }
  if (typeof callback !== 'function') throw new Error('reconcile missing callback parameter')

  try {
    if (!self.state.reconcileStamp) throw new Error('Ledger client initialization incomplete.')
    if (self.state.properties.setting === 'adFree') {
      if (!viewingId) throw new Error('missing viewingId parameter')

      schema = Joi.string().guid().required().description('opaque identifier for viewing submissions')

      validity = Joi.validate(viewingId, schema)
      if (validity.error) throw new Error(validity.error)
    }
  } catch (ex) {
    this._log('reconcile', { errP: true })
    throw ex
  }

  delayTime = this.state.reconcileStamp - underscore.now()
  if (delayTime > 0) {
    this._log('reconcile', { reason: 'not time to reconcile', delayTime: delayTime })
    return callback(null, null, delayTime)
  }
  if (this.state.currentReconcile) {
    delayTime = random.randomInt({ min: msecs.second, max: (this.options.debugP ? 1 : 10) * msecs.minute })
    this._log('reconcile', { reason: 'already reconciling', delayTime: delayTime, reconcileStamp: this.state.reconcileStamp })
    return callback(null, null, delayTime)
  }

  this._log('reconcile', { setting: self.state.properties.setting })
  if (self.state.properties.setting !== 'adFree') {
    throw new Error('setting not (yet) supported: ' + self.state.properties.setting)
  }

  path = prefix + self.credentials.persona.parameters.userId
  self._retryTrip(self, { path: path, method: 'GET', useProxy: true }, function (err, response, body) {
    const surveyorInfo = body
    let i

    self._log('reconcile', { method: 'GET', path: prefix + '...', errP: !!err })
    if (err) return callback(err)

    for (i = self.state.transactions.length - 1; i >= 0; i--) {
      if (self.state.transactions[i].surveyorId !== surveyorInfo.surveyorId) continue

      delayTime = random.randomInt({ min: msecs.second, max: (self.options.debugP ? 1 : 10) * msecs.minute })
      self._log('reconcile',
                { reason: 'awaiting a new surveyorId', delayTime: delayTime, surveyorId: surveyorInfo.surveyorId })
      return callback(null, null, delayTime)
    }

    self.state.currentReconcile = { viewingId: viewingId, surveyorInfo: surveyorInfo, timestamp: 0 }
    self._log('reconcile', { delayTime: msecs.minute })
    callback(null, self.state, msecs.minute)
  })
}

Client.prototype.ballots = function (viewingId) {
  let i, count, transaction

  count = 0
  for (i = this.state.transactions.length - 1; i >= 0; i--) {
    transaction = this.state.transactions[i]
    if ((transaction.votes < transaction.count) && ((transaction.viewingId === viewingId) || (!viewingId))) {
      count += transaction.count - transaction.votes
    }
  }
  return count
}

Client.prototype.vote = function (publisher, viewingId) {
  let i, transaction

  if (!publisher) throw new Error('missing publisher parameter')

  for (i = this.state.transactions.length - 1; i >= 0; i--) {
    transaction = this.state.transactions[i]
    if (transaction.votes >= transaction.count) continue

    if ((transaction.viewingId === viewingId) || (!viewingId)) break
  }
  if (i < 0) return

  this.state.ballots.push({ viewingId: transaction.viewingId,
    surveyorId: transaction.surveyorIds[transaction.votes],
    publisher: publisher,
    offset: transaction.votes
  })
  transaction.votes++

  return this.state
}

Client.prototype.report = function () {
  const entries = this.logging

  this.logging = []
  if (entries.length) return entries
}

Client.prototype.generateKeypair = function () {
  const wallet = this.state.properties && this.state.properties.wallet

  if (!wallet) {
    if (!this.state.properties) this.state.properties = {}

    this.state.properties.wallet = { keyinfo: { seed: braveCrypto.getSeed(SEED_LENGTH) } }
  } else if (!wallet.keyinfo) {
    throw new Error('invalid wallet')
  }
  return this.getKeypair()
}

Client.prototype.getKeypair = function () {
  if (this.state && this.state.properties && this.state.properties.wallet &&
      this.state.properties.wallet.keyinfo && this.state.properties.wallet.keyinfo.seed) {
    return braveCrypto.deriveSigningKeysFromSeed(this.state.properties.wallet.keyinfo.seed, HKDF_SALT)
  }
  throw new Error('invalid or uninitialized wallet')
}

Client.prototype.getWalletPassphrase = function (state, options) {
  if (!state) state = this.state

  const wallet = state.properties && state.properties.wallet

  this._log('getWalletPassphrase')

  if (!wallet) return

  if ((wallet.keyinfo) && (wallet.keyinfo.seed)) {
    const seed = Buffer.from(wallet.keyinfo.seed)
    const passPhrase = passphraseUtil.fromBytesOrHex(seed, options && options.useNiceware)

    return passPhrase && passPhrase.split(' ')
  }
}

Client.prototype.recoverKeypair = function (passPhrase) {
  var seed
  this._log('recoverKeypair')
  try {
    seed = Buffer.from(passphraseUtil.toBytes32(passPhrase))
  } catch (ex) {
    throw new Error('invalid passphrase:' + ex.toString())
  }

  if (seed && seed.length === SEED_LENGTH) {
    if (!this.state.properties) this.state.properties = {}

    this.state.properties.wallet = { keyinfo: { seed: seed } }
  } else {
    throw new Error('internal error, seed returned is invalid')
  }
  return this.getKeypair()
}

Client.prototype.isValidPassPhrase = function (passPhrase) {
  if (!passPhrase || typeof passPhrase !== 'string') {
    return false
  }

  try {
    passphraseUtil.toBytes32(passPhrase)
  } catch (ex) {
    this.memo('isValidPassPhrase', ex.toString())
    return false
  }

  return true
}

Client.prototype.recoverWallet = function (recoveryId, passPhrase, callback) {
  const self = this
  let path, keypair

  try {
    keypair = this.recoverKeypair(passPhrase)
  } catch (ex) {
    return callback(ex)
  }

  path = '/v2/wallet?publicKey=' + braveCrypto.uint8ToHex(keypair.publicKey)
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    if (err) return callback(err)

    self._log('recoverWallet', body)

    if (!body.paymentId) return callback(new Error('invalid response'))

    recoveryId = body.paymentId

    path = '/v2/wallet/' + recoveryId
    self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
      self._log('recoverWallet', { method: 'GET', path: '/v2/wallet/...', errP: !!err })
      if (err) return callback(err)

      self._log('recoverWallet', body)

      if (!body.addresses) return callback(new Error('invalid response'))

      // yuck
      const walletInfo = (self.state.properties && self.state.properties.wallet) || { }

      self.state.properties.wallet = underscore.extend(walletInfo, { paymentId: recoveryId }, underscore.pick(body, [ 'addresses', 'altcurrency' ]))

      return callback(null, self.state, underscore.omit(body, [ 'addresses', 'altcurrency' ]))
    })
  })
}

Client.prototype.busyP = function () {
  const self = this

  const then = new Date().getTime() - (15 * msecs.day)
  let busyP = false

  self.state.ballots.forEach((ballot) => {
    const transaction = underscore.find(self.state.transactions, (transaction) => {
      return (transaction.viewingId === ballot.viewingId)
    })

    if ((!transaction) || (!transaction.submissionStamp) || (!transaction.submissionStamp > then)) return

    busyP = true
    self._log('busyP', underscore.extend({ submissionStamp: transaction.submissionStamp }, ballot))
  })

  return busyP
}

Client.prototype.publisherTimestamp = function (callback) {
  const self = this

  let path

  if (self.options.version === 'v1') return

  path = '/v3/publisher/timestamp'
  self._retryTrip(self, { path: path, method: 'GET', useProxy: true }, function (err, response, body) {
    self._log('publisherInfo', { method: 'GET', path: path, errP: !!err })
    if (err) return callback(err)

    callback(null, body)
  })
}

Client.prototype.publisherInfo = function (publisher, callback) {
  const self = this

  let path

  if (self.options.version === 'v1') return

  path = '/v3/publisher/identity?' + querystring.stringify({ publisher: publisher })
  self._retryTrip(self, { path: path, method: 'GET', useProxy: true }, function (err, response, body) {
    self._log('publisherInfo', { method: 'GET', path: path, errP: !!err })
    if (err) return callback(err, null, response)

    callback(null, body)
  })
}

// batched interface... now a single callback invocation

Client.prototype.publishersInfo = function (publishers, callback) {
  if (this.options.version === 'v1') return

  // initial version is still serialized, future versions will use a new API call.

  if (!Array.isArray(publishers)) publishers = [ publishers ]
  if (publishers.length === 0) return

  if (typeof this.batches === 'undefined') this.batches = 0
  if (!this.publishers) this.publishers = { requests: [], results: [], uniques: [] }
  publishers.forEach((publisher) => {
    if (this.publishers.uniques.indexOf(publisher) !== -1) return

    this.publishers.requests.push(publisher)
    this.publishers.uniques.push(publisher)
  })
  this._publishersInfo(callback)
}

Client.prototype.memo = function (who, args) {
  let what

  if (!this.state.memos) this.state.memos = []
  if (this.state.memos.length > 10) this.state.memos.splice(0, this.state.memos.length - 10)
  if (typeof args !== 'object') {
    what = {reason: args}
  } else {
    what = args
  }

  this.state.memos.push(JSON.stringify({ who: who, what: what || {}, when: underscore.now() }))
  this._log(who, args)
}

Client.prototype._publishersInfo = function (callback) {
  const self = this

  const publisher = underscore.first(self.publishers.requests)
  let results

  if (self.batches > 3) return

  if (!publisher) {
    if (self.batches > 0) return

    results = self.publishers.results
    self.publishers.results = []
    self.publishers.uniques = []
    if (results.length) callback(null, results)
    return
  }

  self.publishers.requests = underscore.rest(self.publishers.requests)

  self.batches++
  self.publisherInfo(publisher, (err, result, response) => {
    if ((err) && (response) && (response.statusCode === 429)) {
      return setTimeout(() => {
        self.batches--
        self.publishersInfo(publisher, callback)
      }, random.randomInt({ min: 1 * msecs.minute, max: 2 * msecs.minute }))
    }

    self.batches--
    self.publishers.results.push(((!err) && (result) ? result : { publisher: publisher, err: err }))

    self._publishersInfo.bind(self)(callback)
  })

  setTimeout(() => self._publishersInfo.bind(self)(callback), random.randomInt({ min: 250, max: 500 }))
}

Client.prototype.getPromotion = function (lang, forPaymentId, callback) {
  const self = this

  let path, params, paymentId
  params = {}

  if (self.options.version === 'v1') return

  if (!callback) {
    callback = lang
    lang = null
    if (typeof callback !== 'function') throw new Error('getPromotion missing callback parameter')
  }

  path = '/v1/grants'
  if (lang) params.lang = lang
  if (forPaymentId) {
    params.paymentId = paymentId = forPaymentId
  } else {
    paymentId = self.state && self.state.properties && self.state.properties.wallet && self.state.properties.wallet.paymentId
    if (paymentId) params.paymentId = paymentId
  }
  if ((lang) || (paymentId)) path += '?' + querystring.stringify(params)
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    self._log('getPromotion', { method: 'GET', path: path, errP: !!err })
    if (err) return callback(err)

    callback(null, body)
  })
}

Client.prototype.setPromotion = function (promotionId, callback) {
  const self = this

  let path

  if (self.options.version === 'v1') return

  path = '/v1/grants/' + self.state.properties.wallet.paymentId
  self._retryTrip(self, { path: path, method: 'PUT', payload: { promotionId: promotionId } }, function (err, response, body) {
    self._log('publisherInfo', { method: 'PUT', path: path, errP: !!err })
    if (err) return callback(err, null, response)

    callback(null, body)
  })
}

/*
 *
 * internal functions
 *
 */

Client.prototype._registerPersona = function (callback) {
  const self = this

  const prefix = self.options.prefix + '/registrar/persona'
  let path

  path = prefix
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    let credential
    let personaId = self.state.personaId || uuid.v4().toLowerCase()

    self._log('_registerPersona', { method: 'GET', path: path, errP: !!err })
    if (err) return callback(err)

    credential = new anonize.Credential(personaId, body.registrarVK)

    self.credentialRequest(credential, function (err, result) {
      let body, keychains, keypair, octets, payload

      if (err) return callback(err)

      if (result.credential) credential = new anonize.Credential(result.credential)

      if (self.options.version === 'v2') {
        keypair = self.generateKeypair()
        body = {
          label: uuid.v4().toLowerCase(),
          currency: 'BAT',
          publicKey: braveCrypto.uint8ToHex(keypair.publicKey)
        }
        octets = stringify(body)
        var headers = {
          digest: 'SHA-256=' + crypto.createHash('sha256').update(octets).digest('base64')
        }
        headers['signature'] = sign({
          headers: headers,
          keyId: 'primary',
          secretKey: braveCrypto.uint8ToHex(keypair.secretKey)
        }, { algorithm: 'ed25519' })
        payload = {
          requestType: 'httpSignature',
          request: {
            headers: headers,
            body: body,
            octets: octets
          }
        }
      }
      payload.proof = result.proof

      path = prefix + '/' + credential.parameters.userId
      self._retryTrip(self, { path: path, method: 'POST', payload: payload }, function (err, response, body) {
        let configuration, currency, days, fee

        self._log('_registerPersona', { method: 'POST', path: prefix + '/...', errP: !!err })
        if (err) return callback(err)

        self.credentialFinalize(credential, body.verification, function (err, result) {
          if (err) return callback(err)

          self.credentials.persona = new anonize.Credential(result.credential)
          self.state.persona = result.credential

          configuration = body.payload && body.payload.adFree
          if (!configuration) {
            self._log('_registerPersona', { error: 'persona registration missing adFree configuration' })
            return callback(new Error('persona registration missing adFree configuration'))
          }

          currency = configuration.currency || 'USD'
          days = configuration.days || 30
          if (!configuration.fee[currency]) {
            if (currency === 'USD') {
              self._log('_registerPersona', { error: 'USD is not supported by the ledger' })
              return callback(new Error('USD is not supported by the ledger'))
            }
            if (!configuration.fee.USD) {
              self._log('_registerPersona', { error: 'neither ' + currency + ' nor USD are supported by the ledger' })
              return callback(new Error('neither ' + currency + ' nor USD are supported by the ledger'))
            }
            currency = 'USD'
          }
          fee = { currency: currency, amount: configuration.fee[currency] }

          // yuck
          const walletInfo = (self.state.properties && self.state.properties.wallet) || { }

          self.state.personaId = personaId
          self.state.properties = { setting: 'adFree',
            fee: fee,
            days: days,
            configuration: body.contributions,
            wallet: underscore.extend(walletInfo, body.wallet, { keychains: keychains })
          }
          self.state.bootStamp = underscore.now()
          if (self.options.verboseP) self.state.bootDate = new Date(self.state.bootStamp)
          self.state.reconcileStamp = self.state.bootStamp + (self.state.properties.days * msecs.day)
          if (self.options.verboseP) self.state.reconcileDate = new Date(self.state.reconcileStamp)

          self._log('_registerPersona', { personaId: personaId, delayTime: msecs.minute })
          callback(null, self.state, msecs.minute)
        })
      })
    })
  })
}

Client.prototype._currentReconcile = function (callback) {
  const self = this

  const amount = self.state.properties.fee.amount
  const currency = self.state.properties.fee.currency
  const prefix = self.options.prefix + '/wallet/'
  const surveyorInfo = self.state.currentReconcile.surveyorInfo
  const viewingId = self.state.currentReconcile.viewingId
  let fee, path, rates, suffix

  suffix = '?' + self._getWalletParams({ amount: amount, currency: currency })
  path = prefix + self.state.properties.wallet.paymentId + suffix
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    let alt, delayTime, keypair, octets, payload

    self._log('_currentReconcile', { method: 'GET', path: prefix + '...?' + suffix, errP: !!err })
    if (err) return callback(err)

    if (!body.unsignedTx) {
      if (body.rates[currency]) {
        alt = (amount / body.rates[currency]).toFixed(4)
      } else {
        self._log('reconcile', { error: currency + ' no longer supported by the ledger' })
      }

      self.state.paymentInfo = underscore.extend(underscore.pick(body, [
        'balance', 'buyURL', 'recurringURL', 'satoshis', 'altcurrency', 'probi'
      ]),
        {
          address: self.state.properties.wallet.addresses && self.state.properties.wallet.addresses.BAT
            ? self.state.properties.wallet.addresses.BAT : self.state.properties.wallet.address,
          addresses: self.state.properties.wallet.addresses,
          amount: amount,
          currency: currency
        })
      self.state.paymentInfo[body.altcurrency ? body.altcurrency : 'btc'] = alt

      delayTime = random.randomInt({ min: msecs.second, max: (self.options.debugP ? 1 : 10) * msecs.minute })
      self._log('_currentReconcile', { reason: 'balance < btc', balance: body.balance, alt: alt, delayTime: delayTime })
      return callback(null, self.state, delayTime)
    }

    const reconcile = (params) => {
      path = prefix + self.state.properties.wallet.paymentId
      payload = underscore.extend({ viewingId: viewingId, surveyorId: surveyorInfo.surveyorId }, params)
      self._retryTrip(self, { path: path, method: 'PUT', payload: payload }, function (err, response, body) {
        let transaction

        self._log('_currentReconcile', { method: 'PUT', path: prefix + '...', errP: !!err })

        delete self.state.currentReconcile

        if (err) return callback(err)

        transaction = { viewingId: viewingId,
          surveyorId: surveyorInfo.surveyorId,
          contribution: {
            fiat: { amount: amount, currency: currency },
            rates: rates,
            satoshis: body.satoshis,
            altcurrency: body.altcurrency,
            probi: body.probi,
            fee: fee
          },
          submissionStamp: body.paymentStamp,
          submissionDate: self.options.verboseP ? new Date(body.paymentStamp) : undefined,
          submissionId: body.hash
        }
        self.state.transactions.push(transaction)

        self.state.reconcileStamp = underscore.now() + (self.state.properties.days * msecs.day)
        if (self.options.verboseP) self.state.reconcileDate = new Date(self.state.reconcileStamp)

        self._updateRules(function (err) {
          if (err) self._log('_updateRules', { message: err.toString() })

          self._log('_currentReconcile', { delayTime: msecs.minute })
          callback(null, self.state, msecs.minute)
        })
      })
    }

    fee = body.unsignedTx.fee
    rates = body.rates
    if (body.altcurrency) {
      keypair = self.getKeypair()
      octets = stringify(body.unsignedTx)
      var headers = {
        digest: 'SHA-256=' + crypto.createHash('sha256').update(octets).digest('base64')
      }
      headers['signature'] = sign({
        headers: headers,
        keyId: 'primary',
        secretKey: braveCrypto.uint8ToHex(keypair.secretKey)
      }, { algorithm: 'ed25519' })
      payload = {
        requestType: 'httpSignature',
        signedTx: {
          headers: headers,
          body: body.unsignedTx,
          octets: octets
        }
      }

      return reconcile(payload)
    }
  })
}

Client.prototype._registerViewing = function (viewingId, callback) {
  const self = this

  const prefix = self.options.prefix + '/registrar/viewing'
  let path = prefix

  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, body) {
    let credential

    self._log('_registerViewing', { method: 'GET', path: path, errP: !!err })
    if (err) return callback(err)

    credential = new anonize.Credential(viewingId, body.registrarVK)

    self.credentialRequest(credential, function (err, result) {
      if (err) return callback(err)

      if (result.credential) credential = new anonize.Credential(result.credential)

      path = prefix + '/' + credential.parameters.userId
      self._retryTrip(self, { path: path, method: 'POST', payload: { proof: result.proof } }, function (err, response, body) {
        let i

        self._log('_registerViewing', { method: 'POST', path: prefix + '/...', errP: !!err })
        if (err) return callback(err)

        self.credentialFinalize(credential, body.verification, function (err, result) {
          if (err) return callback(err)

          for (i = self.state.transactions.length - 1; i >= 0; i--) {
            if (self.state.transactions[i].viewingId !== viewingId) continue

            // NB: use of `underscore.extend` requires that the parameter be `self.state.transactions[i]`
            underscore.extend(self.state.transactions[i],
              { credential: result.credential,
                surveyorIds: body.surveyorIds,
                count: body.surveyorIds.length,
                satoshis: body.satoshis,
                altcurrency: body.altcurrency,
                probi: body.probi,
                votes: 0
              })
            self._log('_registerViewing', { delayTime: msecs.minute })
            return callback(null, self.state, msecs.minute)
          }

          callback(new Error('viewingId ' + viewingId + ' not found in transaction list'))
        })
      })
    })
  })
}

Client.prototype._prepareBallot = function (ballot, transaction, callback) {
  const self = this

  const credential = new anonize.Credential(transaction.credential)
  const prefix = self.options.prefix + '/surveyor/voting/'
  let path

  path = prefix + encodeURIComponent(ballot.surveyorId) + '/' + credential.parameters.userId
  self._retryTrip(self, { path: path, method: 'GET', useProxy: true }, function (err, response, body) {
    let delayTime, now

    self._log('_prepareBallot', { method: 'GET', path: prefix + '...', errP: !!err })
    if (err) return callback(transaction.err = err)

    ballot.prepareBallot = underscore.defaults(body, { server: self.options.server })

    now = underscore.now()
    delayTime = random.randomInt({ min: 10 * msecs.second, max: (self.options.debugP ? 1 : 5) * msecs.minute })
    ballot.delayStamp = now + delayTime
    if (self.options.verboseP) ballot.delayDate = new Date(ballot.delayStamp)

    if (delayTime > msecs.minute) delayTime = msecs.minute
    self._log('_prepareBallot', { delayTime: delayTime })
    callback(null, self.state, delayTime)
  })
}

Client.prototype._commitBallot = function (ballot, transaction, callback) {
  const self = this

  const credential = new anonize.Credential(transaction.credential)
  const prefix = self.options.prefix + '/surveyor/voting/'
  const surveyor = new anonize.Surveyor(ballot.prepareBallot)
  let path

  path = prefix + encodeURIComponent(surveyor.parameters.surveyorId)

  self.credentialSubmit(credential, surveyor, { publisher: ballot.publisher }, function (err, result) {
    if (err) return callback(err)

    self._retryTrip(self, { path: path, method: 'PUT', useProxy: true, payload: result.payload }, function (err, response, body) {
      let i

      self._log('_commitBallot', { method: 'PUT', path: prefix + '...', errP: !!err })
      if (err) return callback(transaction.err = err)

      if (!transaction.ballots) transaction.ballots = {}
      if (!transaction.ballots[ballot.publisher]) transaction.ballots[ballot.publisher] = 0
      transaction.ballots[ballot.publisher]++

      for (i = self.state.ballots.length - 1; i >= 0; i--) {
        if (self.state.ballots[i].surveyorId !== ballot.surveyorId) continue

        self.state.ballots.splice(i, 1)
        break
      }
      if (i < 0) console.log('\n\nunable to find ballot surveyorId=' + ballot.surveyorId)

      self._log('_commitBallot', { delayTime: msecs.minute })
      callback(null, self.state, msecs.minute)
    })
  })
}

Client.prototype._getWalletParams = function (params) {
  let result = 'refresh=true'

  if (params.amount) result += '&amount=' + params.amount
  if (params.currency) result += '&' + (params.currency === 'BAT' ? 'alt' : '') + 'currency=' + params.currency

  return result
}

Client.prototype._log = function (who, args) {
  const debugP = this.options ? this.options.debugP : false
  const loggingP = this.options ? this.options.loggingP : false

  if (debugP) console.log(JSON.stringify({ who: who, what: args || {}, when: underscore.now() }, null, 2))
  if (loggingP) this.logging.push({ who: who, what: args || {}, when: underscore.now() })
}

Client.prototype._updateRules = function (callback) {
  const self = this

  let path

  self.state.updatesStamp = underscore.now() + msecs.hour
  if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)

  path = '/v1/publisher/ruleset?consequential=true'
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, ruleset) {
    let validity

    self._log('_updateRules', { method: 'GET', path: '/v1/publisher/ruleset', errP: !!err })
    if (err) return callback(err)

    validity = Joi.validate(ruleset, batPublisher.schema)
    if (validity.error) {
      self._log('_updateRules', { error: validity.error })
      return callback(new Error(validity.error))
    }

    if (!underscore.isEqual(self.state.ruleset || [], ruleset)) {
      self.state.ruleset = ruleset

      batPublisher.rules = ruleset
    }

    self._updateRulesV2(callback)
  })
}

Client.prototype._updateRulesV2 = function (callback) {
  const self = this

  let path

  self.state.updatesStamp = underscore.now() + msecs.hour
  if (self.options.verboseP) self.state.updatesDate = new Date(self.state.updatesStamp)

  path = '/v2/publisher/ruleset?limit=512&excludedOnly=false'
  if (self.state.rulesV2Stamp) path += '&timestamp=' + self.state.rulesV2Stamp
  self._retryTrip(self, { path: path, method: 'GET' }, function (err, response, ruleset) {
    let c, i, rule, ts

    self._log('_updateRules', { method: 'GET', path: '/v2/publisher/ruleset', errP: !!err })
    if (err) return callback(err)

    if (ruleset.length === 0) return callback()

    if (!self.state.rulesetV2) self.state.rulesetV2 = []
    self.state.rulesetV2 = self.state.rulesetV2.concat(ruleset)
    rule = underscore.last(ruleset)

    if (ruleset.length < 512) {
      ts = rule.timestamp.split('')
      for (i = ts.length - 1; i >= 0; i--) {
        c = ts[i]
        if (c < '9') {
          ts[i] = String.fromCharCode(ts[i].charCodeAt(0) + 1)
          break
        }
        ts[i] = '0'
      }

      self.state.rulesV2Stamp = ts.join('')
    } else {
      self.state.rulesV2Stamp = rule.timestamp
    }

    setTimeout(function () { self._updateRulesV2.bind(self)(callback) }, 3 * msecs.second)
  })
}

// round-trip to the ledger with retries!
Client.prototype._retryTrip = (self, params, callback, retry) => {
  let method

  const loser = (reason) => { setTimeout(() => { callback(new Error(reason)) }, 0) }
  const rangeP = (n, min, max) => { return ((min <= n) && (n <= max) && (n === parseInt(n, 10))) }

  if (!retry) {
    retry = underscore.defaults(params.backoff || {}, {
      algorithm: 'binaryExponential', delay: 5 * 1000, retries: 3, tries: 0
    })
    if (!rangeP(retry.delay, 1, 30 * 1000)) return loser('invalid backoff delay')
    if (!rangeP(retry.retries, 0, 10)) return loser('invalid backoff retries')
    if (!rangeP(retry.tries, 0, retry.retries - 1)) return loser('invalid backoff tries')
  }
  method = retry.method || backoff[retry.algorithm]
  if (typeof method !== 'function') return loser('invalid backoff algorithm')
  method = method(retry.delay)

  self.roundtrip(params, (err, response, payload) => {
    const code = response && Math.floor(response.statusCode / 100)

    if ((!err) || (code !== 5) || (retry.retries-- < 0)) return callback(err, response, payload)

    return setTimeout(() => { self._retryTrip(self, params, callback, retry) }, method(++retry.tries))
  })
}

Client.prototype._roundTrip = function (params, callback) {
  const self = this

  const server = self.options.server
  const client = server.protocol === 'https:' ? https : http
  let request, timeoutP

  params = underscore.extend(underscore.pick(self.options.server, [ 'protocol', 'hostname', 'port' ]), params)
  params.headers = underscore.defaults(params.headers || {},
                                       { 'content-type': 'application/json; charset=utf-8', 'accept-encoding': '' })

  request = client.request(underscore.omit(params, [ 'useProxy', 'payload' ]), function (response) {
    let body = ''

    if (timeoutP) return
    response.on('data', function (chunk) {
      body += chunk.toString()
    }).on('end', function () {
      let payload

      if (params.timeout) request.setTimeout(0)

      if (self.options.verboseP) {
        console.log('[ response for ' + params.method + ' ' + server.protocol + '//' + server.hostname + params.path + ' ]')
        console.log('>>> HTTP/' + response.httpVersionMajor + '.' + response.httpVersionMinor + ' ' + response.statusCode +
                   ' ' + (response.statusMessage || ''))
        underscore.keys(response.headers).forEach(function (header) {
          console.log('>>> ' + header + ': ' + response.headers[header])
        })
        console.log('>>>')
        console.log('>>> ' + body.split('\n').join('\n>>> '))
      }
      if (Math.floor(response.statusCode / 100) !== 2) {
        self._log('_roundTrip', { error: 'HTTP response ' + response.statusCode })
        return callback(new Error('HTTP response ' + response.statusCode), response, null)
      }

      try {
        payload = (response.statusCode !== 204) ? JSON.parse(body) : null
      } catch (err) {
        return callback(err, response, null)
      }

      try {
        callback(null, response, payload)
      } catch (err0) {
        if (self.options.verboseP) console.log('callback: ' + err0.toString() + '\n' + err0.stack)
      }
    }).setEncoding('utf8')
  }).on('error', function (err) {
    callback(err)
  }).on('timeout', function () {
    timeoutP = true
    callback(new Error('timeout'))
  })
  if (params.payload) request.write(JSON.stringify(params.payload))
  request.end()

  if (!self.options.verboseP) return

  console.log('<<< ' + params.method + ' ' + params.protocol + '//' + params.hostname + params.path)
  underscore.keys(params.headers).forEach(function (header) { console.log('<<< ' + header + ': ' + params.headers[header]) })
  console.log('<<<')
  if (params.payload) console.log('<<< ' + JSON.stringify(params.payload, null, 2).split('\n').join('\n<<< '))
}

Client.prototype.credentialWorker = function (operation, payload, callback) {
  const self = this

  const msgno = self.seqno++
  const request = { msgno: msgno, operation: operation, payload: payload }
  let worker

  self.callbacks[msgno] = { verboseP: self.options.verboseP, callback: callback }

  worker = self.options.createWorker('bat-client/worker.js')
  worker.onmessage = function (evt) {
    const response = evt.data
    const state = self.callbacks[response.msgno]

    if (!state) return console.log('! >>> not expecting msgno=' + response.msgno)

    delete self.callbacks[response.msgno]
    if (state.verboseP) console.log('! >>> ' + JSON.stringify(response, null, 2))
    state.callback(response.err, response.result)
    worker.terminate()
  }
  worker.onerror = function (message, stack) {
    console.log('! >>> worker error: ' + message)
    console.log(stack)
    try { worker.terminate() } catch (ex) { }
  }

  worker.on('start', function () {
    if (self.options.verboseP) console.log('! <<< ' + JSON.stringify(request, null, 2))
    worker.postMessage(request)
  })
  worker.start()
}

Client.prototype.credentialRoundTrip = function (operation, payload, callback) {
  const msgno = this.seqno++
  const request = { msgno: msgno, operation: operation, payload: payload }

  this.callbacks[msgno] = { verboseP: this.options.verboseP, callback: callback }
  if (this.options.verboseP) console.log('! <<< ' + JSON.stringify(request, null, 2))
  this.helper.send(request)
}

Client.prototype.credentialRequest = function (credential, callback) {
  let proof

  if (this.options.createWorker) return this.credentialWorker('request', { credential: JSON.stringify(credential) }, callback)

  if (this.helper) this.credentialRoundTrip('request', { credential: JSON.stringify(credential) }, callback)

  try { proof = credential.request() } catch (ex) { return callback(ex) }
  callback(null, { proof: proof })
}

Client.prototype.credentialFinalize = function (credential, verification, callback) {
  if (this.options.createWorker) {
    return this.credentialWorker('finalize', { credential: JSON.stringify(credential), verification: verification }, callback)
  }

  if (this.helper) {
    return this.credentialRoundTrip('finalize', { credential: JSON.stringify(credential), verification: verification },
                                    callback)
  }

  try { credential.finalize(verification) } catch (ex) { return callback(ex) }
  callback(null, { credential: JSON.stringify(credential) })
}

Client.prototype.credentialSubmit = function (credential, surveyor, data, callback) {
  let payload

  if (this.options.createWorker) {
    return this.credentialWorker('submit',
                                 { credential: JSON.stringify(credential), surveyor: JSON.stringify(surveyor), data: data },
                                 callback)
  }

  if (this.helper) {
    return this.credentialRoundTrip('submit',
                                    { credential: JSON.stringify(credential), surveyor: JSON.stringify(surveyor), data: data },
                                    callback)
  }

  try { payload = { proof: credential.submit(surveyor, data) } } catch (ex) { return callback(ex) }
  return callback(null, { payload: payload })
}

Client.prototype._fuzzing = function (synopsis) {
  let duration = 0
  let remaining = this.state.reconcileStamp - underscore.now()
  let advance, memo, ratio, window

  if ((!synopsis) ||
      (remaining > (3 * msecs.day)) ||
      (this.options && this.options.noFuzzing) ||
      (this.boolion(process.env.LEDGER_NO_FUZZING))) return

  synopsis.prune()
  underscore.keys(synopsis.publishers).forEach((publisher) => {
    duration += synopsis.publishers[publisher].duration
  })

  // at the moment hard-wired to 30 minutes every 30 days
  ratio = duration / (30 * msecs.minute)
  memo = { duration: duration, ratio1: ratio, numFrames: synopsis.options.numFrames, frameSize: synopsis.options.frameSize }
  window = synopsis.options.numFrames * synopsis.options.frameSize
  if (window > 0) ratio *= (30 * msecs.day) / window
  if (ratio >= 1.0) return

  memo.window = window
  memo.ratio2 = ratio

  advance = Math.round((this.state.properties.days * msecs.day) * (1.0 - ratio))
  memo.advance1 = advance
  if (advance > (3 * msecs.day)) advance = 3 * msecs.day
  memo.advance2 = advance
  if (advance) this.state.reconcileStamp += advance
  memo.reconcileStamp = this.state.reconcileStamp
  memo.reconcileDate = new Date(memo.reconcileStamp)

  this.memo('_fuzzing', memo)
}
/*
 *
 * utilities
 *
 */

Client.prototype.boolion = function (value) {
  const f = {
    undefined: function () {
      return false
    },

    boolean: function () {
      return value
    },

    // handles `Infinity` and `NaN`
    number: function () {
      return (!!value)
    },

    string: function () {
      return ([ 'n', 'no', 'false', '0' ].indexOf(value.toLowerCase()) === -1)
    },

    // handles `null`
    object: function () {
      return (!!value)
    }
  }[typeof value] || function () { return false }

  return f()
}

Client.prototype.numbion = function (value) {
  if (typeof value === 'string') value = parseInt(value, 10)

  const f = {
    undefined: function () {
      return 0
    },

    boolean: function () {
      return (value ? 1 : 0)
    },

    // handles `Infinity` and `NaN`
    number: function () {
      return (Number.isFinite(value) ? value : 0)
    },

    object: function () {
      return (value ? 1 : 0)
    }
  }[typeof value] || function () { return 0 }

  return f()
}

module.exports = Client
