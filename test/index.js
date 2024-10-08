'use strict';

var crypto = require('crypto');
var constants = require('constants');
var parseKey = require('parse-asn1');
var BN = require('bn.js');
var Buffer = require('safe-buffer').Buffer;
var test = require('tape');

var crt = require('../');

var fixtures = require('./fixtures');

test('browserify-rsa', function (t) {
	fixtures.forEach(function (fixture, i) {
		var key = new Buffer(fixture, 'hex');
		var priv = parseKey(key);

		t.test('fixture ' + (i + 1), function (st) {
			var r;

			for (var j1 = 1; j1 < 31; ++j1) {
				r = crt.getr(priv);
				st.equal(
					String(r.gcd(priv.modulus)),
					'1',
					'r is coprime with n ' + (i + 1) + ' run ' + j1
				);
			}

			st.test('compared to node encryption', { skip: !crypto.privateDecrypt }, function (s2t) {
				var len = priv.modulus.byteLength();
				for (var j2 = 1; j2 < 41; ++j2) {
					do {
						r = new BN(crypto.randomBytes(len));
					} while (r.cmp(priv.modulus) >= 0);
					var buf = r.toArrayLike(Buffer, 'be');
					if (buf.byteLength < priv.modulus.byteLength()) {
						var tmp = new Buffer(priv.modulus.byteLength() - buf.byteLength);
						tmp.fill(0);
						buf = Buffer.concat([tmp, buf]);
					}
					var nodeEncrypt = crypto.privateDecrypt({
						padding: constants.RSA_NO_PADDING,
						key: key
					}, buf).toString('hex');
					s2t.equal(
						crt(buf, priv).toString('hex'),
						nodeEncrypt,
						'round trip key ' + (i + 1) + ' run ' + j2 + ' equal encrypts'
					);
				}

				s2t.end();
			});

			st.end();
		});
	});
});
