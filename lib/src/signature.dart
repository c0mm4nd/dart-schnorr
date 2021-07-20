import 'dart:core';

import 'package:elliptic/elliptic.dart';
import 'package:ninja_asn1/ninja_asn1.dart';

import 'err.dart';
import 'utils.dart';

class ErrInvalidCurve implements Exception {}

class ErrInvalidPriv implements Exception {}

class Signature {
  late BigInt R;
  late BigInt S;

  Signature.fromRS(this.R, this.S);

  Signature.fromASN1(List<int> asn1Bytes) {
    var p = ASN1Sequence.decode(asn1Bytes);
    R = (p.children[0] as ASN1Integer).value;
    S = (p.children[1] as ASN1Integer).value;
  }

  Signature.fromASN1Hex(String asn1Hex) {
    var asn1Bytes = List<int>.generate(asn1Hex.length >> 1,
        (i) => int.parse(asn1Hex.substring(i * 2, i * 2 + 2), radix: 16));
    var p = ASN1Sequence.decode(asn1Bytes);
    R = (p.children[0] as ASN1Integer).value;
    S = (p.children[1] as ASN1Integer).value;
  }

  List<int> toASN1() {
    return ASN1Sequence([ASN1Integer(R), ASN1Integer(S)]).encode();
  }

  String toASN1Hex() {
    var asn1 = toASN1();
    return List<String>.generate(
        asn1.length, (i) => asn1[i].toRadixString(16).padLeft(2, '0')).join();
  }

  /// [toString] equals to [toASN1Hex]
  @override
  String toString() {
    return toASN1Hex();
  }
}

/// [deterministicSign] signs a hash (which should be the result of hashing a larger message)
/// using the private key, priv. If the hash is longer than the bit-length of the
/// private key's curve order, the hash will be truncated to that length. It
/// returns the signature as a pair of integers.
Signature deterministicSign(PrivateKey priv, List<int> hash) {
  var curve = priv.curve;

  if ((priv.D < BigInt.one) || priv.D > curve.n - BigInt.one) {
    throw ErrInvalidPriv(); //the private key must be an integer in the range 1..n-1
  }

  var d = intToByte(curve, priv.D);
  var k0 = deterministicGetK0(curve, d, hash);

  var pointR = curve.scalarBaseMul(intToByte(curve, k0));
  print(pointR.X);
  print(pointR.Y);
  var k = getK(curve, pointR, k0); // getEvenKey
  print(k);
  var pointP = curve.scalarBaseMul(d);
  var rX = intToByte(curve, pointR.X);
  print(pointP.X.toString() +
      ' ' +
      pointP.Y.toString() +
      ' ' +
      rX.toString() +
      ' ' +
      hash.toString());
  var e = getE(curve, pointP, rX, hash);
  print('e:' + e.toString());
  e = e * priv.D;
  print(e);
  k = k + e;
  print(k);
  k = k % curve.n;
  print(k);

  var R = pointR.X;
  var S = k;
  return Signature.fromRS(R, S);
}

/// [verify] a signature of a 32 byte message against the public key.
/// Returns an error if verification fails.
/// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
bool verify(PublicKey pub, List<int> hash, Signature sig) {
  var curve = pub.curve;

  if (!curve.isOnCurve(pub)) {
    throw SchnorrException('public key is not on curve ' + curve.name);
  }

  var r = sig.R;
  if (r >= curve.p) {
    throw SchnorrException('r is larger than or equal to field size');
  }

  var s = sig.S;
  if (s >= curve.n) {
    throw SchnorrException('s is larger than or equal to curve order');
  }

  var e = getE(curve, pub, intToByte(curve, r), hash);
  var sG = curve.scalarBaseMul(intToByte(curve, s));
  var eP = curve.scalarMul(pub, intToByte(curve, e));
  eP.Y = curve.p - eP.Y;
  var R = curve.add(sG, eP);

  if ((R.X.sign == 0 && R.Y.sign == 0) ||
      jacobi(R.Y, curve.p) != 1 ||
      R.X != r) {
    return false;
  }

  return true;
}

// BatchVerify verifies a list of 64 byte signatures of 32 byte messages against the public keys.
// Returns an error if verification fails.
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#batch-verification
bool batchVerify(List<PublicKey> publicKeys, List<List<int>> messages,
    List<Signature> signatures) {
  if (publicKeys.isEmpty) {
    throw SchnorrException(
        'publicKeys must be an array with one or more elements');
  }
  if (messages.isEmpty) {
    throw SchnorrException(
        'messages must be an array with one or more elements');
  }
  if (signatures.isEmpty) {
    throw SchnorrException(
        'signatures must be an array with one or more elements');
  }
  if (publicKeys.length != messages.length ||
      messages.length != signatures.length) {
    throw SchnorrException(
        'all parameters must be an array with the same length');
  }

  var curve = publicKeys[0].curve;

  var ls = BigInt.zero;
  var a = BigInt.one;
  var rs = AffinePoint();

  var big7 = BigInt.from(7);

  var result = false;
  for (final i in signatures.asMap().keys) {
    var signature = signatures[i];
    var publicKey = publicKeys[i];
    var message = messages[i];
    if (curve != publicKey.curve) {
      throw SchnorrException('publickeys must be on the same curve');
    }

    if (!curve.isOnCurve(publicKey)) {
      throw SchnorrException('publickey is not on the curve');
    }

    var r = signature.R;
    if (r >= curve.p) {
      throw SchnorrException('r is larger than or equal to field size');
    }
    var s = signature.S;
    if (s >= curve.n) {
      throw SchnorrException('s is larger than or equal to curve order');
    }

    var e = getE(curve, publicKey, intToByte(curve, r), message);

    var r2 = r.pow(3);
    r2 = r2 + big7;
    r2 = r2 % curve.p;
    var c = r2;
    var exp = curve.p + BigInt.one;
    exp = exp >> 2;

    var y = c.modPow(exp, curve.p);

    if (y.modPow(BigInt.two, curve.p) != c) {
      break;
    }

    var R = AffinePoint.fromXY(r, y);

    if (i != 0) {
      a = deterministicGetRandA(curve);
    }

    var aR = curve.scalarMul(R, intToByte(curve, a));
    var ae = (a * e);
    var aeHex = ae.toRadixString(16).padLeft((ae.bitLength + 7) >> 3, '0');
    var aeBytes = List<int>.generate((ae.bitLength + 7) >> 3,
        (index) => int.parse(aeHex.substring(2 * index, 2 * index + 2)));
    var aeP = curve.scalarMul(publicKey, aeBytes);
    rs = curve.add(rs, aR);
    rs = curve.add(rs, aeP);
    s = s * a;
    ls = ls + s;
  }

  var G = curve.scalarBaseMul(intToByte(curve, ls % curve.n));
  if (G != rs) {
    return false;
  }

  return result;
}

// AggregateSignatures aggregates multiple signatures of different private keys over
// the same message into a single 64 byte signature.
Signature aggregateSign(List<PrivateKey> privateKeys, List<int> message) {
  if (privateKeys.isEmpty) {
    throw SchnorrException(
        'privateKeys must be an array with one or more elements');
  }

  var k0s = List<BigInt>.filled(privateKeys.length, BigInt.zero);
  var P = AffinePoint();
  var R = AffinePoint();
  var curve = privateKeys[0].curve;
  var privMap = privateKeys.asMap();

  for (final i in privMap.keys) {
    if (privateKeys[i].curve != curve) {
      throw SchnorrException('privatekeys must be on the same curve');
    }

    if (privateKeys[i].D < BigInt.one ||
        privateKeys[i].D > curve.n - BigInt.one) {
      throw SchnorrException(
          'the private key must be an integer in the range 1..n-1');
    }

    var d = intToByte(curve, privateKeys[i].D);
    var k0i = deterministicGetK0(curve, d, message);

    var Ri = curve.scalarBaseMul(intToByte(curve, k0i));
    var Pi = curve.scalarBaseMul(d);

    k0s[i] = k0i;

    R = curve.add(R, Ri);
    P = curve.add(P, Pi);
  }

  var rX = intToByte(curve, R.X);
  var e = getE(curve, P, rX, message);
  var s = BigInt.zero;

  for (final j in k0s.asMap().keys) {
    var k = getK(curve, R, k0s[j]);
    k = k + (e * privateKeys[j].D);
    s = s + k;
  }

  return Signature.fromRS(R.X, s % curve.n);
}

// CombinePublicKeys can combine public keys
PublicKey combinePublicKeys(List<PublicKey> pubs) {
  if (pubs.isEmpty) {
    throw SchnorrException('pks must be an array with one or more elements');
  }

  if (pubs.length == 1) {
    return pubs[0];
  }

  var p = AffinePoint.fromXY(pubs[0].X, pubs[0].Y);
  var curve = pubs[0].curve;
  for (var i = 1; i < pubs.length; i++) {
    if (pubs[i].curve != curve) {
      throw SchnorrException('publickeys must be on the same curve');
    }

    p = curve.add(p, pubs[i]);
  }

  return PublicKey.fromPoint(curve, p);
}
