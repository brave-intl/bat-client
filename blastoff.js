#!/usr/bin/env node

var fs = require('fs')
var path = require('path')
var underscore = require('underscore')
var url = require('url')
var uuid = require('uuid')

/*
 *
 * parse the command arguments
 *
 */

var usage = function () {
  console.log('usage: node ' + path.basename(process.argv[1]) +
              ' [ -d ] [ -f file | -p personaID] [ -l ] [ -s https://... ] [ -v ]')
  process.exit(1)
}

var options, server
var argv = process.argv.slice(2)
var configFile = process.env.CONFIGFILE
var personaID = process.env.PERSONA
var debugP = process.env.DEBUG || false
var loggingP = process.env.LOGGING || false
var verboseP = process.env.VERBOSE || false

while (argv.length > 0) {
  if (argv[0].indexOf('-') !== 0) break

  if (argv[0] === '-d') {
    debugP = true
    argv = argv.slice(1)
    continue
  }
  if (argv[0] === '-l') {
    loggingP = true
    argv = argv.slice(1)
    continue
  }
  if (argv[0] === '-v') {
    verboseP = true
    argv = argv.slice(1)
    continue
  }

  if (argv.length === 1) usage()

  if (argv[0] === '-f') configFile = argv[1]
  else if (argv[0] === '-s') server = argv[1]
  else if (argv[0] === '-p') personaID = argv[1].toLowerCase()
  else usage()

  argv = argv.slice(2)
}
if ((!configFile) && (!personaID)) usage()
if (!configFile) configFile = 'config.json'

if (!server) server = process.env.SERVER || 'https://ledger-staging.brave.com'
if (server.indexOf('http') !== 0) server = 'https://' + server
server = url.parse(server)

options = { server: server, debugP: debugP, loggingP: loggingP, verboseP: verboseP, version: 'v2' }

/*
 *
 * create/recover state
 *
 */

var client

var callback = function (err, result, delayTime) {
  var entries = client.report()

  if (err) oops('client', err)
  if (verboseP) console.log('callback delayTime=' + delayTime + ' resultP=' + (!!result))

  if (!result) return run(delayTime)

  if (entries) entries.forEach((entry) => { console.log('*** ' + JSON.stringify(entry)) })

  if (result) {
    client.getWalletProperties(5, 'USD', (err, body) => {
      if (err) return console.log('wallet properties error=' + err.toString())

      console.log('!!! wallet properties=' + JSON.stringify(body, null, 2))
      if (body.balance > 10.0) {
        setTimeout(() => {
          client.setTimeUntilReconcile(underscore.now(), (err, result) => {
            if (err) return console.log('setTimeUntilReconcile error=' + err.toString())

            console.log('preparing for reconciliation')
          }, 0)
        })
      }
    })
  }

  if (result.paymentInfo) {
    console.log(JSON.stringify(result.paymentInfo, null, 2))
    if (result.paymentInfo.address) {
      console.log('\nplease click here for payment: bitcoin:' + result.paymentInfo.address + '?amount=' +
                  result.paymentInfo.btc + '\n')
    } else {
      console.log('\nplease click here for payment: ether:' + result.paymentInfo.addresses.BAT + '?token=BAT&amount=' +
                  result.paymentInfo.BAT + '\n')
    }
  }
  delete result.publishersV2
  delete result.rulesetV2
  fs.writeFile(configFile, JSON.stringify(result, null, 2), { encoding: 'utf8', mode: parseInt('644', 8) }, function (err) {
    if (err) oops(configFile, err)

    // at least one transaction
    // with all ballots created
    // and all ballots submitted
    if ((result.transactions) && (result.transactions.length) &&
        (result.transactions[0].count === result.transactions[0].votes) &&
        (!result.ballots.length)) process.exit(0)

    run(delayTime)
  })
}

fs.readFile(personaID ? '/dev/null' : configFile, { encoding: 'utf8' }, function (err, data) {
  var state = err ? null : data ? JSON.parse(data) : {}

  client = require('./index.js')(personaID, options, state)
  if (client.sync(callback) === true) run(10 * 1000)
})

/*
 *
 * process the command
 *
 */

var reconcileP = false

var run = function (delayTime) {
  var viewingId = uuid.v4().toLowerCase()

  if (delayTime > 0) return setTimeout(() => { if (client.sync(callback)) return run(0) }, delayTime)

  if (!client.isReadyToReconcile()) return client.reconcile(viewingId, callback)
  if (reconcileP) {
    console.log('already reconciling.\n')
    return run(60 * 1000)
  }

  reconcileP = true
  client.reconcile(viewingId, callback)
}

var oops = function (s, err) {
  console.log(s + ': ' + err.toString())
  console.log(err.stack)
  process.exit(1)
}
