var crypto = require('crypto')
var constants = require('constants')
var parseKey = require('parse-asn1')
var BN = require('bn.js')
var test = require('tape')
var crt = require('../')

test('browserify-rsa', function (t) {
  require('./fixtures').forEach(function (fixture, i) {
    var key = new Buffer(fixture, 'hex')
    var priv = parseKey(key)

    t.test('fixture ' + (i + 1), function (st) {
      for (var j1 = 1; j1 < 31; ++j1) {
        var r = crt.getr(priv)
        st.equal(
          String(r.gcd(priv.modulus)),
          '1',
          'r is coprime with n ' + (i + 1) + ' run ' + j1
        )
      }

      var len = priv.modulus.byteLength()
      for (var j2 = 1; j2 < 41; ++j2) {
        var r
        do {
          r = new BN(crypto.randomBytes(len))
        } while (r.cmp(priv.modulus) >= 0)
        var buf = r.toArrayLike(Buffer, 'be')
        if (buf.byteLength < priv.modulus.byteLength()) {
          var tmp = new Buffer(priv.modulus.byteLength() - buf.byteLength)
          tmp.fill(0)
          buf = Buffer.concat([tmp, buf])
        }
        var nodeEncrypt = crypto.privateDecrypt({
          padding: constants.RSA_NO_PADDING,
          key: key
        }, buf).toString('hex')
        st.equal(
          crt(buf, priv).toString('hex'),
          nodeEncrypt,
          'round trip key ' + (i + 1) + ' run ' + j2 + ' equal encrypts'
        )
      }

      st.end()
    })
  })
})
