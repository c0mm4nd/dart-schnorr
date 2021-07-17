import 'package:elliptic/elliptic.dart';
import 'package:ninja_asn1/ninja_asn1.dart';

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
  var e = getE(curve, pointP, rX, hash);
  e = e * priv.D;
  k = k + e;
  k = k % curve.n;

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
    throw Exception('public key is not on curve ' + curve.name);
  }

  var r = sig.R;
  if (r >= curve.p) {
    throw Exception('r is larger than or equal to field size');
  }

  var s = sig.S;
  if (s >= curve.n) {
    throw Exception('s is larger than or equal to curve order');
  }

  var e = getE(curve, pub, intToByte(curve, r), hash);
  print(e);
  var sG = curve.scalarBaseMul(intToByte(curve, s));
  print(sG.X.toString() + ' ' + sG.Y.toString());
  var eP = curve.scalarMul(pub, intToByte(curve, e));
  print(eP.X.toString() + ' ' + eP.Y.toString());
  eP.Y = curve.p - eP.Y;
  print(eP.Y.toString());
  var R = curve.add(sG, eP);
  print(R.X.toString() + ' ' + R.Y.toString());

  if ((R.X.sign == 0 && R.Y.sign == 0) || jacobi(R.Y, curve.p) != 1 || R.X != r) {
    return false;
  }

  return true;
}
