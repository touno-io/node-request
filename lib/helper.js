/**
 * script for generating a SHA1 fingerprint for a remote SSL certificate
 */
let urlib = require('url'),
	_ = require('lodash'),
	request = require('request'),
	debug = require('debug')('request-ssl');

function requestFingerprintForURL(arg, callback) {
	let url = urlib.parse(arg),
		host = url.host || arg,
		port = url.port || (!url.host || url.protocol==='https:' ? 443 : 80),
		cb = callback || function(err) { err && console.log(err); }
	let fingerprint = getFingerprintForURL(host)
	if (fingerprint) return cb(null, fingerprint);

	let req = request({url:'https://'+host+':'+port+'/',method:'get'});
	req.on('response',function(resp){
		// in case of a redirect
		debug('TLS response final url %s, begin with %s',resp.request.uri.host,url);
		var socket = resp.socket;
		var fingerprint = socket.getPeerCertificate().fingerprint;
		// var shouldMatch = requestFingerprintForURL(url);
		// debug('TLS server fingerprint is: %s, url: %s', fingerprint, 'https://'+host+':'+port+'/');
		debug('TLS server certificate',socket.getPeerCertificate());
		debug('TLS cipher %j',socket.getCipher());
		debug('TLS remoteAddress/port: %s:%d',socket.remoteAddress,socket.remotePort);
		req.abort();
		cb(null, fingerprint);
	});
	req.on('socket', function(socket){
		socket.on('secureConnect', function(){
			debug('TLS connection established to %s',url);
			if (!socket.authorized) {
				req.abort();
			}
		});
	});
}

/**
 * given a url return a domain part
 */
function getDomain (url) {
	var domain = _.isObject(url) ? url.host : urlib.parse(url).host;
	return domain || url;
}

/**
 * lookup a fingerprint for a given URL by using the domain. returns null if
 * not found
 */
function getFingerprintForURL (url) {
	var domain = getDomain(url);
	var found = global.requestSSLFingerprints[domain];
	debug('getFingerprintForURL %s -> %s=%s',url,domain,found);
	if (!found) {
		// try a wildcard search
		var u = urlib.parse(domain),
			tokens = (u && u.host || domain).split('.');
		domain = '*.'+tokens.splice(tokens.length > 1 ? 0 : 1).join('.');
		found = global.requestSSLFingerprints[domain];
		debug('getFingerprintForURL (wildcard) %s -> %s=%s',url,domain,found);
	}
	return found;
}

exports.requestFingerprintForURL = requestFingerprintForURL;
exports.getDomain = getDomain
exports.getFingerprintForURL = getFingerprintForURL

if (module.id===".") {
	var path = require('path');
	var arg = process.argv[2];
	if (!arg) {
		console.error("node "+path.basename(process.argv[1])+" <url>");
		process.exit(1);
	}
	requestFingerprintForURL(arg, function(err,fingerprint){
		if (err) {
			console.error(err);
			process.exit(1);
		}
		console.log(fingerprint);
	});
}
