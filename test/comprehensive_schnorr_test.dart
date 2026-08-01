import 'dart:math';

import 'package:elliptic/elliptic.dart';
import 'package:schnorr/schnorr.dart';
import 'package:schnorr/src/utils.dart';
import 'package:test/test.dart';

List<int> _message(int seed) =>
    List<int>.generate(32, (index) => (seed + index * 17) & 0xff);

PrivateKey _privateKey(Curve curve, BigInt value) => PrivateKey(curve, value);

Matcher _schnorrError(String message) => isA<SchnorrException>()
    .having((error) => error.message, 'message', message);

void main() {
  late Curve curve;

  setUp(() {
    curve = getS256();
  });

  group('deterministicSign', () {
    test('round-trips across several private keys', () {
      final privateValues = <BigInt>[
        BigInt.one,
        BigInt.two,
        BigInt.parse(
            'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
            radix: 16),
        curve.n - BigInt.one,
      ];

      for (var index = 0; index < privateValues.length; index++) {
        final privateKey = _privateKey(curve, privateValues[index]);
        final message = _message(index + 1);
        final signature = deterministicSign(privateKey, message);

        expect(verify(privateKey.publicKey, message, signature), isTrue,
            reason: 'private key index $index should round-trip');
      }
    });

    test('is deterministic for the same key and message', () {
      final privateKey = _privateKey(curve, BigInt.from(42));
      final message = _message(9);

      final first = deterministicSign(privateKey, message);
      final second = deterministicSign(privateKey, message);

      expect(second.R, first.R);
      expect(second.S, first.S);
    });

    test('changes when either the message or private key changes', () {
      final firstKey = _privateKey(curve, BigInt.from(42));
      final secondKey = _privateKey(curve, BigInt.from(43));
      final firstMessage = _message(10);
      final secondMessage = _message(11);

      final original = deterministicSign(firstKey, firstMessage);
      final changedMessage = deterministicSign(firstKey, secondMessage);
      final changedKey = deterministicSign(secondKey, firstMessage);

      expect(<BigInt>[changedMessage.R, changedMessage.S],
          isNot(<BigInt>[original.R, original.S]));
      expect(<BigInt>[changedKey.R, changedKey.S],
          isNot(<BigInt>[original.R, original.S]));
    });

    test('rejects private keys outside one through n minus one', () {
      expect(
        () => deterministicSign(_privateKey(curve, BigInt.zero), _message(12)),
        throwsA(isA<ErrInvalidPriv>()),
      );
      expect(
        () => deterministicSign(_privateKey(curve, curve.n), _message(12)),
        throwsA(isA<ErrInvalidPriv>()),
      );
    });
  });

  group('verify', () {
    test('accepts a valid BIP Schnorr vector', () {
      final publicKey = PublicKey.fromHex(curve,
          '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
      final message = List<int>.filled(32, 0);
      final signature = Signature.fromRS(
        BigInt.parse(
            '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF6',
            radix: 16),
        BigInt.parse(
            '7031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05',
            radix: 16),
      );

      expect(verify(publicKey, message, signature), isTrue);
    });

    test('returns false for tampered R and tampered S', () {
      final privateKey = _privateKey(curve, BigInt.from(99));
      final message = _message(13);
      final signature = deterministicSign(privateKey, message);

      expect(
        verify(privateKey.publicKey, message,
            Signature.fromRS(signature.R + BigInt.one, signature.S)),
        isFalse,
      );
      expect(
        verify(
            privateKey.publicKey,
            message,
            Signature.fromRS(
                signature.R, (signature.S + BigInt.one) % curve.n)),
        isFalse,
      );
    });

    test('returns false for the wrong public key and wrong message', () {
      final signingKey = _privateKey(curve, BigInt.from(100));
      final otherKey = _privateKey(curve, BigInt.from(101));
      final message = _message(14);
      final signature = deterministicSign(signingKey, message);

      expect(verify(otherKey.publicKey, message, signature), isFalse);
      expect(verify(signingKey.publicKey, _message(15), signature), isFalse);
    });

    test('throws when R reaches the field size', () {
      final privateKey = _privateKey(curve, BigInt.from(102));
      final signature = deterministicSign(privateKey, _message(16));

      expect(
        () => verify(privateKey.publicKey, _message(16),
            Signature.fromRS(curve.p, signature.S)),
        throwsA(_schnorrError('r is larger than or equal to field size')),
      );
    });

    test('throws when S reaches the curve order', () {
      final privateKey = _privateKey(curve, BigInt.from(103));
      final signature = deterministicSign(privateKey, _message(17));

      expect(
        () => verify(privateKey.publicKey, _message(17),
            Signature.fromRS(signature.R, curve.n)),
        throwsA(_schnorrError('s is larger than or equal to curve order')),
      );
    });

    test('throws for a mutated off-curve public key', () {
      final privateKey = _privateKey(curve, BigInt.from(104));
      final publicKey = privateKey.publicKey;
      final message = _message(18);
      final signature = deterministicSign(privateKey, message);
      publicKey.X = BigInt.zero;
      publicKey.Y = BigInt.zero;

      expect(
        () => verify(publicKey, message, signature),
        throwsA(_schnorrError('public key is not on curve secp256k1')),
      );
    });
  });

  group('batchVerify', () {
    test('accepts a genuine multi-signature batch', () {
      final privateKeys = <PrivateKey>[
        _privateKey(curve, BigInt.from(201)),
        _privateKey(curve, BigInt.from(202)),
        _privateKey(curve, BigInt.from(203)),
        _privateKey(curve, BigInt.from(204)),
      ];
      final messages = List<List<int>>.generate(
          privateKeys.length, (index) => _message(20 + index));
      final signatures = List<Signature>.generate(privateKeys.length,
          (index) => deterministicSign(privateKeys[index], messages[index]));

      expect(
        batchVerify(privateKeys.map((key) => key.publicKey).toList(), messages,
            signatures),
        isTrue,
      );
    });

    test('rejects a batch containing one tampered signature', () {
      final privateKeys = <PrivateKey>[
        _privateKey(curve, BigInt.from(205)),
        _privateKey(curve, BigInt.from(206)),
        _privateKey(curve, BigInt.from(207)),
      ];
      final messages = <List<int>>[_message(24), _message(25), _message(26)];
      final signatures = List<Signature>.generate(privateKeys.length,
          (index) => deterministicSign(privateKeys[index], messages[index]));
      signatures[1] = Signature.fromRS(
          signatures[1].R, (signatures[1].S + BigInt.one) % curve.n);

      expect(
        batchVerify(privateKeys.map((key) => key.publicKey).toList(), messages,
            signatures),
        isFalse,
      );
    });

    test('throws for every empty input and for mismatched lengths', () {
      final privateKey = _privateKey(curve, BigInt.from(208));
      final message = _message(27);
      final signature = deterministicSign(privateKey, message);

      expect(
          () => batchVerify(
              <PublicKey>[], <List<int>>[message], <Signature>[signature]),
          throwsA(isA<SchnorrException>()));
      expect(
          () => batchVerify(<PublicKey>[privateKey.publicKey], <List<int>>[],
              <Signature>[signature]),
          throwsA(isA<SchnorrException>()));
      expect(
          () => batchVerify(<PublicKey>[privateKey.publicKey],
              <List<int>>[message], <Signature>[]),
          throwsA(isA<SchnorrException>()));
      expect(
          () => batchVerify(
              <PublicKey>[privateKey.publicKey, privateKey.publicKey],
              <List<int>>[message],
              <Signature>[signature]),
          throwsA(_schnorrError(
              'all parameters must be an array with the same length')));
    });
  });

  group('aggregateSign and combinePublicKeys', () {
    test('verifies two-key and three-key aggregate signatures', () {
      final privateKeys = <PrivateKey>[
        _privateKey(curve, BigInt.from(301)),
        _privateKey(curve, BigInt.from(302)),
        _privateKey(curve, BigInt.from(303)),
      ];
      final message = _message(30);

      for (final count in <int>[2, 3]) {
        final selectedKeys = privateKeys.sublist(0, count);
        final signature = aggregateSign(selectedKeys, message);
        final publicKey = combinePublicKeys(
            selectedKeys.map((key) => key.publicKey).toList());

        expect(verify(publicKey, message, signature), isTrue,
            reason: '$count-key aggregate should verify');
      }
    });

    test('combinePublicKeys returns its single input', () {
      final publicKey = _privateKey(curve, BigInt.from(304)).publicKey;

      final combined = combinePublicKeys(<PublicKey>[publicKey]);

      expect(identical(combined, publicKey), isTrue);
      expect(combined, publicKey);
    });

    test('combinePublicKeys equals iterative point addition', () {
      final publicKeys = <PublicKey>[
        _privateKey(curve, BigInt.from(305)).publicKey,
        _privateKey(curve, BigInt.from(306)).publicKey,
        _privateKey(curve, BigInt.from(307)).publicKey,
        _privateKey(curve, BigInt.from(308)).publicKey,
      ];
      var expected = AffinePoint.fromXY(publicKeys.first.X, publicKeys.first.Y);
      for (final publicKey in publicKeys.skip(1)) {
        expected = curve.add(expected, publicKey);
      }

      final combined = combinePublicKeys(publicKeys);

      expect(combined.X, expected.X);
      expect(combined.Y, expected.Y);
    });

    test('empty key lists throw SchnorrException', () {
      expect(
          () => combinePublicKeys(<PublicKey>[]),
          throwsA(
              _schnorrError('pks must be an array with one or more elements')));
      expect(() => aggregateSign(<PrivateKey>[], _message(31)),
          throwsA(isA<SchnorrException>()));
    });
  });

  group('Signature serialization', () {
    test('fromRS toASN1 and fromASN1 round-trip', () {
      final original = Signature.fromRS(
          BigInt.parse('80ffffffffffffffff', radix: 16),
          BigInt.parse('ff00112233445566778899', radix: 16));

      final decoded = Signature.fromASN1(original.toASN1());

      expect(decoded.R, original.R);
      expect(decoded.S, original.S);
    });

    test('toASN1Hex and fromASN1Hex round-trip', () {
      final original =
          Signature.fromRS(curve.p - BigInt.one, curve.n - BigInt.one);
      final encoded = original.toASN1Hex();

      final decoded = Signature.fromASN1Hex(encoded);

      expect(decoded.R, original.R);
      expect(decoded.S, original.S);
      expect(original.toString(), encoded);
    });
  });

  group('utils', () {
    test('jacobi identifies known residues and non-residues', () {
      final modulus = BigInt.from(7);

      for (final residue in <int>[1, 2, 4]) {
        expect(jacobi(BigInt.from(residue), modulus), 1,
            reason: '$residue is a quadratic residue modulo 7');
      }
      for (final nonResidue in <int>[3, 6]) {
        expect(jacobi(BigInt.from(nonResidue), modulus), -1,
            reason: '$nonResidue is a quadratic non-residue modulo 7');
      }
      expect(jacobi(BigInt.zero, modulus), 0);
    });

    test('intToByte uses exactly the curve byte length', () {
      final bytes = intToByte(curve, BigInt.from(0x0102));

      expect(bytes, hasLength((curve.bitSize + 7) ~/ 8));
      expect(bytes.take(bytes.length - 2), everyElement(0));
      expect(bytes.sublist(bytes.length - 2), <int>[1, 2]);
    });

    test('deterministicGetRandA stays in one through n minus one', () {
      final random = Random(8675309);

      for (var i = 0; i < 64; i++) {
        final coefficient = deterministicGetRandA(curve, random);
        expect(coefficient, greaterThanOrEqualTo(BigInt.one));
        expect(coefficient, lessThan(curve.n));
      }
    });

    test('getE is stable and getK selects the Jacobi-positive nonce', () {
      final privateKey = _privateKey(curve, BigInt.from(401));
      final nonce = BigInt.from(17);
      final noncePoint = curve.scalarBaseMul(intToByte(curve, nonce));
      final rBytes = intToByte(curve, noncePoint.X);
      final message = _message(40);

      final firstE = getE(curve, privateKey.publicKey, rBytes, message);
      final secondE = getE(curve, privateKey.publicKey, rBytes, message);
      final changedE = getE(curve, privateKey.publicKey, rBytes, _message(41));

      expect(firstE, secondE);
      expect(firstE, greaterThanOrEqualTo(BigInt.zero));
      expect(firstE, lessThan(curve.n));
      expect(changedE, isNot(firstE));

      final selectedNonce = getK(curve, noncePoint, nonce);
      final selectedPoint =
          curve.scalarBaseMul(intToByte(curve, selectedNonce));
      expect(
          selectedNonce == nonce || selectedNonce == curve.n - nonce, isTrue);
      expect(selectedPoint.X, noncePoint.X);
      expect(jacobi(selectedPoint.Y, curve.p), 1);
    });

    test('deterministic nonce and encoding helpers are stable', () {
      final privateKey = _privateKey(curve, BigInt.from(402));
      final message = _message(42);
      final privateBytes = intToByte(curve, privateKey.D);

      final firstNonce = deterministicGetK0(curve, privateBytes, message);
      final secondNonce = deterministicGetK0(curve, privateBytes, message);
      final encodedPublicKey = marshal(curve, privateKey.publicKey);

      expect(firstNonce, secondNonce);
      expect(firstNonce, greaterThanOrEqualTo(BigInt.one));
      expect(firstNonce, lessThan(curve.n));
      expect(encodedPublicKey, hasLength(33));
      expect(encodedPublicKey.first, anyOf(2, 3));
      expect(highestFactorsOf2(BigInt.from(40)), 3);
    });
  });
}
