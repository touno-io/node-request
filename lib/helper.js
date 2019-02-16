const _ = require('lodash')
const request = require('request')
const debug = require('./debug')('request-ssl')

/**
 * script for generating a SHA1 fingerprint for a remote SSL certificate
 */
const requestFingerprintForURL = (arg, callback) => {
  const url = new URL(arg)
  const host = url.host || arg
  const port = url.port || (!url.host || url.protocol === 'https:' ? 443 : 80)
  const cb = callback || (err => { err && console.log(err) })
  let fingerprint = getFingerprintForURL(host)
  if (fingerprint) return cb(null, fingerprint)

  let req = request({ url: `https://${host}:${port}/`, method: 'get' })
  req.on('response', resp => {
    // in case of a redirect
    debug('TLS response final url %s, begin with %s', resp.request.uri.host, url)
    let socket = resp.socket
    let fingerprint = socket.getPeerCertificate().fingerprint
    // let shouldMatch = requestFingerprintForURL(url)
    // debug('TLS server fingerprint is: %s, url: %s', fingerprint, 'https://'+host+':'+port+'/')
    debug('TLS server certificate', socket.getPeerCertificate())
    debug('TLS cipher %j', socket.getCipher())
    debug('TLS remoteAddress/port: %s:%d', socket.remoteAddress, socket.remotePort)
    req.abort()
    cb(null, fingerprint)
  })
  req.on('socket', socket => {
    socket.on('secureConnect', () => {
      debug('TLS connection established to %s', url)
      if (!socket.authorized) req.abort()
    })
  })
}

/**
 * given a url return a domain part
 */
const getDomain = url => {
  let domain = _.isObject(url) ? url.host : new URL(url).host
  return domain || url
}

/**
 * lookup a fingerprint for a given URL by using the domain. returns null if
 * not found
 */
const getFingerprintForURL = url => {
  let domain = getDomain(url)
  let found = global.requestSSLFingerprints[domain]
  debug('getFingerprintForURL %s -> %s=%s', url, domain, found)
  if (!found) {
    // try a wildcard search
    let u = new URL(domain)
    let tokens = ((u && u.host) || domain).split('.')
    domain = `*.${tokens.splice(tokens.length > 1 ? 0 : 1).join('.')}`
    found = global.requestSSLFingerprints[domain]
    debug('getFingerprintForURL (wildcard) %s -> %s=%s', url, domain, found)
  }
  return found
}

exports.requestFingerprintForURL = requestFingerprintForURL
exports.getDomain = getDomain
exports.getFingerprintForURL = getFingerprintForURL

if (module.id === '.') {
  let path = require('path')
  let arg = process.argv[2]
  if (!arg) {
    console.error(`node ${path.basename(process.argv[1])} <url>`)
    process.exit(1)
  }
  requestFingerprintForURL(arg, (err, fingerprint) => {
    if (err) {
      console.error(err)
      process.exit(1)
    }
    console.log(fingerprint)
  })
}
