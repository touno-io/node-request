const wrench = require('wrench')
const request = require('../')
const fs = require('fs')
const path = require('path')
const assert = require('assert')

const TMP = path.join(require('os').tmpdir(), String(+new Date()))

describe('pinned url domain google', function () {
	this.timeout(30000)

	let fingerprint1
	let fingerprint2

	before(() => fs.mkdirSync(TMP))
	after(() => fs.existsSync(TMP) && wrench.rmdirSyncRecursive(TMP))
	afterEach(() => request.resetLastURL())

	it('should fetch www.google.com fingerprint', done => {
		request.getFingerprintForURL('https://www.google.com', (err, f) => {
			fingerprint1 = f
			assert.equal(err, null)
			assert.equal(typeof fingerprint1, 'string')
			request.addFingerprint('https://www.google.com',fingerprint1)
			done()
		})
	})

	it('should fetch google.com fingerprint', done => {
		request.getFingerprintForURL('https://google.com', (err, f) => {
			fingerprint2 = f
			assert.equal(err, null)
			assert.equal(typeof fingerprint2, 'undefined')
			done()
		})
	})


	it('should pin https://google.com with #request.get', done => {
		request.get('https://google.com', function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			assert.equal(request.getLastURL(), 'https://www.google.com')
			done()
		})
	})

	it('should pin https://www.google.com with #request.get', done => {
		request.get('https://www.google.com', function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			done()
		})
	})

	it('should support getting fingerprint using domain instead of URL', done => {
		request.getFingerprintForURL('www.google.com', (err, f) => {
			assert.equal(err, null)
			assert.equal(typeof f, 'string')
			request.addFingerprint('https://www.google.com', f)
			done()
		})
	})

	it('should support getting fingerprint with combo SSL cert', done => {
		request.getFingerprintForURL('software.appcelerator.com', (err, f) => {
			assert.equal(err, null)
			assert.equal(typeof f, 'string')
			assert.equal(f, '9C:A2:2B:30:1A:A8:F9:FC:A7:9D:E5:84:1E:E0:C9:42:C6:9A:6D:A3')
			done()
		})
	})

	it('should request initializer', done => {
		this.timeout(5000)
		request.getFingerprintForURL('www.google.com', (err, f) => {
			assert.equal(err, null)
			assert.notEqual(f, undefined)
			request.addFingerprint('https://www.google.com', f)
			let init = false
			request.registerInitializer(callback => {
				init = true
				callback()
			})
			request.get('https://www.google.com', (err, resp) => {
				assert.equal(err, null)
				assert(init)
				done()
			})
		})
	})

	it('should remove fingerprints', () => {
		request.removeFingerprint('https://www.google.com')
	})

	it('should fail to pin https://google.com with #request.get', done => {
		request.get('https://google.com', function(err,resp,body){
			assert.notEqual(err, null)
			assert(err instanceof Object)
			assert.equal(err.message, 'SSL authorization failed. URL: www.google.com does not have a valid fingerprint which can be used to verify the SSL certificate.')
			done()
		})
	})

	it('should fail to pin https://www.google with #request.get using bad fingerprint', done => {
		request.addFingerprint('https://google.com','FF:11:22:33:44')
		request.addFingerprint('https://www.google.com','AA:BB:CC:DD:EE')
		request.get('https://www.google.com', function(err,resp,body){
			assert.notEqual(err, null)
			assert(err instanceof Object)
			assert.equal(err.message, 'SSL authorization failed. URL to www.google.com is not authorized for SSL. Mismatched SSL fingerprint. This likely means that the URL doesn\'t point to the expected server or there is an unexpected man-in-the-middle.')
			done()
		})
	})

	it('should add fingerprints from directory', done => {
		var fn1 = fs.writeFileSync(path.join(TMP,'www.google.com'),fingerprint1)
		// var fn2 = fs.writeFileSync(path.join(TMP,'google.com'),fingerprint2)
		request.addFingerprintDirectory(TMP)
		request.get('https://www.google.com', function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			assert.equal(request.getLastURL(), 'https://www.google.com')
			done()
		})
	})

	it('should request with URL string', done => {
		request('https://www.google.com', function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			assert.equal(request.getLastURL(), 'https://www.google.com')
			done()
		})
	})

	it('should request with URL in object', done => {
		request({url:'https://www.google.com'}, function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			assert.equal(request.getLastURL(), 'https://www.google.com')
			done()
		})
	})

	it('should request with URI in object', done => {
		request({uri:'https://www.google.com'}, function(err,resp,body){
			assert.equal(err, null)
			assert.equal(typeof resp, 'object')
			assert.equal(typeof body, 'string')
			assert.equal(request.getLastURL(), 'https://www.google.com')
			done()
		})
	})

	it('should send error if no callback specified', done => {
		var req = request('https://www.yahoo.com')
		req.on('error', function(e){
			assert.equal(typeof e, 'object')
			assert.equal(e.message, 'SSL authorization failed. URL: www.yahoo.com does not have a valid fingerprint which can be used to verify the SSL certificate.')
			done()
		})
	})

	it('should skip for non-SSL', done => {
		var req = request('http://www.google.com')
		req.on('error', done)
		req.on('end',  () => {
			assert.equal(request.getLastURL(), null)
			done()
		})
	})

	it('should remove all fingerprints', done => {
		request.removeAllFingerprints()
		var req = request('https://www.google.com')
		req.on('error', function(e){
			assert.equal(typeof e, 'object')
			assert.equal(e.message, 'SSL authorization failed. URL: www.google.com does not have a valid fingerprint which can be used to verify the SSL certificate.')
			done()
		})
	})

	it('should fail is adding fingerprint without no domain', () => {
		assert.throws( () => {
			request.addFingerprint()
		}, 'Error: missing name')
	})

	it('should fail is adding fingerprint without no fingerprint', () => {
		assert.throws( () => {
			request.addFingerprint('name')
		}, 'Error: missing fingerprint')
	})

	it('should support getting the request library itself', () => {
		assert.equal(typeof request.request, 'function')
	})

})