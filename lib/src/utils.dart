import 'package:crypto/crypto.dart';
import 'package:elliptic/elliptic.dart';

/// [hashToInt] converts a hash value to an integer. There is some disagreement
/// about how this is done. [NSA] suggests that this is done in the obvious
/// manner, but [SECG] truncates the hash to the bit-length of the curve order
/// first. We follow [SECG] because that's what OpenSSL does. Additionally,
/// OpenSSL right shifts excess bits from the number if the hash is too large
/// and we mirror that too.
BigInt hashToInt(List<int> hash, Curve c) {
  var orderBits = c.n.bitLength;
  var orderBytes = (orderBits + 7) ~/ 8;
  if (hash.length > orderBytes) {
    hash = hash.sublist(0, orderBytes);
  }

  var ret = BigInt.parse(
      List<String>.generate(
          hash.length, (i) => hash[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  var excess = hash.length * 8 - orderBits;
  if (excess > 0) {
    ret >> excess;
  }
  return ret;
}

class ErrZeroK0 implements Exception {}

BigInt deterministicGetK0(Curve curve, List<int> d, List<int> hash) {
  var h = sha256.convert(d + hash).bytes;

  var i = BigInt.parse(
      List<String>.generate(
          h.length, (i) => h[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  var k0 = i % curve.n;

  if (k0.sign == 0) {
    throw ErrZeroK0(); //"k0 is zero"
  }

  return k0;
}

List<int> intToByte(Curve curve, BigInt i) {
  var byteLen = (curve.bitSize + 7) ~/ 8;
  var hex = i.toRadixString(16).padLeft(byteLen * 2, '0');

  return List<int>.generate(
      byteLen, (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16));
}

BigInt getK(Curve curve, AffinePoint pointR, BigInt k0) {
	if (big.Jacobi(Ry, Curve.P) == 1) {
		return k0;
	}

	return curve.n -  k0;
}

func getE(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m[:]...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}