/* jshint asi: true, node: true, laxbreak: true, laxcomma: true, undef: true, unused: true */
/* global self */

const anonize = require('node-anonize2-relic-emscripten')

self.onmessage = function (evt) {
  const request = evt.data

  const d = function (err, result) {
    self.postMessage({ msgno: request.msgno, err: err, result: result })
  }

  const f = {
    request:
      function () {
        const credential = new anonize.Credential(request.payload.credential)
        const proof = credential.request()

        return { credential: JSON.stringify(credential), proof: proof }
      },

    finalize:
      function () {
        const credential = new anonize.Credential(request.payload.credential)

        credential.finalize(request.payload.verification)
        return { credential: JSON.stringify(credential) }
      },

    submit:
      function () {
        if (request.payload.multiple) {
          if (!request.payload.ballots) {
            return { payload: null }
          }

          let payload = []
          request.payload.ballots.forEach(ballot => {
            const credential = new anonize.Credential(ballot.credential)
            const surveyor = new anonize.Surveyor(ballot.surveyor)

            payload.push({
              surveyorId: surveyor.parameters.surveyorId,
              proof: credential.submit(surveyor, { publisher: ballot.publisher })
            })
          })

          return { payload }
        }

        const credential = new anonize.Credential(request.payload.credential)
        const surveyor = new anonize.Surveyor(request.payload.surveyor)
        return { payload: { proof: credential.submit(surveyor, request.payload.data) } }
      }
  }[request.operation]
  if (!f) return d('invalid operation')

  try {
    d(null, f())
  } catch (ex) {
    d(ex.toString())
  }
}
