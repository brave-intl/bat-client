const path = require('path')
const rimraf = require('rimraf')

const rootDir = path.join(__dirname, '..')

process.env.NODE_ENV = process.env.NODE_ENV || 'development'

module.exports.nodeModules = () => {
  console.warn('removing node_modules...')
  rimraf.sync(path.join(rootDir, 'node_modules'))
}

module.exports.app = () => {
  module.exports.nodeModules()
  console.log('done')
}

var cmd = process.argv[2]
if (cmd) {
  module.exports[cmd]()
} else {
  module.exports.app()
}
