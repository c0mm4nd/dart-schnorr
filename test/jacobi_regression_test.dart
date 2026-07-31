import 'package:elliptic/elliptic.dart';
import 'package:schnorr/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('highestFactorsOf2 / jacobi regression', () {
    test('highestFactorsOf2 counts trailing zeros incl. exact powers of two',
        () {
      expect(highestFactorsOf2(BigInt.from(1)), 0);
      expect(highestFactorsOf2(BigInt.from(2)), 1);
      expect(highestFactorsOf2(BigInt.from(4)), 2);
      expect(highestFactorsOf2(BigInt.from(8)), 3);
      expect(highestFactorsOf2(BigInt.from(16)), 4);
      expect(highestFactorsOf2(BigInt.from(40)), 3); // 8 * 5
      expect(highestFactorsOf2(BigInt.from(96)), 5); // 32 * 3
    });

    test('jacobi is correct when the numerator reduces to a power of two', () {
      // 7^2 == 3 (mod 23), so 3 is a quadratic residue mod 23.
      expect(jacobi(BigInt.from(3), BigInt.from(23)), 1);
      // 5 is a quadratic non-residue mod 23.
      expect(jacobi(BigInt.from(5), BigInt.from(23)), -1);

      // Cross-check against Euler's criterion on the secp256k1 field prime,
      // exercising power-of-two numerators (2, 8, 2^40).
      var p = getS256().p;
      for (var a in [
        BigInt.two,
        BigInt.from(8),
        BigInt.one << 40,
        BigInt.from(3),
        BigInt.from(7),
      ]) {
        var euler = a.modPow((p - BigInt.one) >> 1, p);
        var expected = euler == BigInt.one ? 1 : -1;
        expect(jacobi(a, p), expected, reason: 'a=$a');
      }
    });
  });
}
