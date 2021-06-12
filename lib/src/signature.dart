import 'package:elliptic/elliptic.dart';
import 'package:ninja_asn1/ninja_asn1.dart';
import 'dart:math';

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
    var asn1Bytes = List<int>.generate(asn1Hex.length ~/ 2,
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

/// [signature] signs a hash (which should be the result of hashing a larger message)
/// using the private key, priv. If the hash is longer than the bit-length of the
/// private key's curve order, the hash will be truncated to that length. It
/// returns the signature as a pair of integers.
Signature signature(PrivateKey priv, List<int> hash) {
  var curve = priv.curve;

	if ((priv.D < BigInt.one) || priv.D >  curve.n  - BigInt.one {
		throw ErrInvalidPriv(); //the private key must be an integer in the range 1..n-1
	}

	var d = intToByte(curve, priv.D);
	var k0 = deterministicGetK0(curve, d, hash);

	var pointR = curve.scalarBaseMul(intToByte(curve, k0));
	var k = getK(pointR.Y, k0);

	var pointP = curve.scalarBaseMul(d);
	var rX = intToByte(curve, pointR.X);
	var e = getE(pointP, rX, hash);
	e = e* priv.D;
	k = k+ e;
	k = k % curve.n;

	var R = pointR.X;
	var S = k;
	return Signature.fromRS(R, S);
}

/// [verify] verifies the signature in r, s of hash using the public key, pub.
/// Its return value records whether the signature is valid.
bool verify(PublicKey pub, List<int> hash, Signature sig) {
  // See [NSA] 3.4.2
  var curve = pub.curve;
  var byteLen = (curve.bitSize + 7) ~/ 8;

  if (sig.R.sign <= 0 || sig.S.sign <= 0) {
    return false;
  }

  if (sig.R >= curve.n || sig.S >= curve.n) {
    return false;
  }

  var e = hashToInt(hash, curve);
  var w = sig.S.modInverse(curve.n);

  var u1 = e * w;
  u1 = u1 % curve.n;
  var u2 = sig.R * w;
  u2 = u2 % curve.n;

  // Check if implements S1*g + S2*p
  var hexU1 = u1.toRadixString(16).padLeft(byteLen * 2, '0');
  var hexU2 = u2.toRadixString(16).padLeft(byteLen * 2, '0');
  var p1 = curve.scalarBaseMul(List<int>.generate(hexU1.length ~/ 2,
      (i) => int.parse(hexU1.substring(i * 2, i * 2 + 2), radix: 16)));
  var p2 = curve.scalarMul(
      pub,
      List<int>.generate(hexU2.length ~/ 2,
          (i) => int.parse(hexU2.substring(i * 2, i * 2 + 2), radix: 16)));
  var p = curve.add(p1, p2);

  if (p.X.sign == 0 && p.Y.sign == 0) {
    return false;
  }

  p.X = p.X % curve.n;
  return p.X == sig.R;
}
