const util = require('util')

/**
 * useful for debugging
 */
function logInspect(x) {
  console.log(util.inspect(x, {depth: null}))
}

module.exports = {
  logInspect,
}