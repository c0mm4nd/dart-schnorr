import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:elliptic/elliptic.dart';

import 'err.dart';

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
  // Right-shift the excess low bits (SECG/OpenSSL bits2int).
  var excess = hash.length * 8 - orderBits;
  if (excess > 0) {
    ret = ret >> excess;
  }
  return ret;
}

BigInt deterministicGetK0(Curve curve, List<int> d, List<int> hash) {
  var h = sha256.convert(d + hash).bytes;

  var i = BigInt.parse(
      List<String>.generate(
          h.length, (i) => h[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  var k0 = i % curve.n;

  if (k0.sign == 0) {
    throw SchnorrException('k0 is zero');
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
  if (jacobi(pointR.Y, curve.p) == 1) {
    return k0;
  }

  return curve.n - k0;
}

BigInt getE(Curve curve, AffinePoint pointP, List<int> rX, List<int> m) {
  var r = rX + marshal(curve, pointP);
  r = r + m;
  var h = sha256.convert(r).bytes;
  var i = BigInt.parse(
      List<String>.generate(
          h.length, (i) => h[i].toRadixString(16).padLeft(2, '0')).join(),
      radix: 16);
  return i % curve.n;
}

/// [marshal] converts a point into the form specified in section 2.3.3 of the
/// SEC 1 standard.
List<int> marshal(Curve curve, AffinePoint p) {
  var hex = curve.publicKeyToCompressedHex(PublicKey.fromPoint(curve, p));

  return List<int>.generate(hex.length ~/ 2,
      (i) => int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16));
}

/// [jacobi] calcs the jacobi symbol (a.k.a. the Legendre symbol).
int jacobi(BigInt x, BigInt y) {
  if (y.isEven) {
    throw Exception(
        'invalid 2nd argument to jacobi: need odd int but got' + y.toString());
  }

  // We use the formulation described in chapter 2, section 2.4,
  // "The Yacas Book of Algorithms":
  // http://yacas.sourceforge.net/Algo.book.pdf

  // var c BigInt
  var a = x;
  var b = y;
  var c = BigInt.zero;
  var j = 1;

  if (b.isNegative) {
    if (a.isNegative) {
      j = -1;
    }
    b = -b;
  }

  var big3 = BigInt.one + BigInt.two;
  var big5 = big3 + BigInt.two;
  var big7 = big5 + BigInt.two;

  while (true) {
    if (b == BigInt.one) {
      return j;
    }
    if (a == BigInt.zero) {
      return 0;
    }

    a = a % b;
    if (a == BigInt.zero) {
      return 0;
    }
    // a > 0

    // Find the largest power of 2 that divides a. Say, a = 2s c
    // where c is odd. Replace ab by cb (−1)s b 2−1 8 (iden
    // handle factors of 2 in 'a'
    var s = highestFactorsOf2(a);
    if (s & 1 != 0) {
      var bmod8 = b & big7;
      if (bmod8 == big3 || bmod8 == big5) {
        j = -j;
      }
    }

    c = a >> s; // a = 2^s*c

    // swap numerator and denominator
    if (b & big3 == big3 && c & big3 == big3) {
      j = -j;
    }
    a = b;
    b = c;
  }
}

int highestFactorsOf2(BigInt x) {
  // Number of trailing zero bits, i.e. the exponent of the largest power of 2
  // dividing x (0 for x == 0). Used by jacobi to factor out powers of two.
  if (x == BigInt.zero) {
    return 0;
  }
  var count = 0;
  while ((x & BigInt.one) == BigInt.zero) {
    x = x >> 1;
    count++;
  }
  return count;
}

// deterministicGetRandA returns a cryptographically secure, uniformly
// distributed batch-verification coefficient in [1, n-1]. An existing
// [Random] may be supplied to avoid constructing a new secure RNG per call.
BigInt deterministicGetRandA(Curve curve, [Random? rng]) {
  var rand = rng ?? Random.secure();
  var n = curve.n;
  var byteLen = (n.bitLength + 7) >> 3;
  var excess = byteLen * 8 - n.bitLength;

  while (true) {
    var bytes = List<int>.generate(byteLen, (_) => rand.nextInt(256));
    var a = BigInt.zero;
    for (var b in bytes) {
      a = (a << 8) | BigInt.from(b & 0xff);
    }
    if (excess > 0) {
      a = a >> excess;
    }
    if (a >= BigInt.one && a < n) {
      return a;
    }
  }
}
