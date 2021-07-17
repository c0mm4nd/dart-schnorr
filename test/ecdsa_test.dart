import 'package:elliptic/elliptic.dart';
import 'package:schnorr/schnorr.dart';
import 'package:schnorr/src/utils.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('Usage Test', () {
      var ec = getS256();
      var priv = PrivateKey.fromHex(ec,
          'd07b57eb3cd1a308b2fa04d97552f00b1d59efc0200affd1edafc98700ce3290');
      var pub = priv.publicKey;
      print(priv);
      print(pub);
      var hashHex =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      var hash = List<int>.generate(hashHex.length ~/ 2,
          (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
      var sig = deterministicSign(priv, hash);
      print(sig.R.toRadixString(16).padLeft(32, '0') +
          ' ' +
          sig.S.toRadixString(16).padLeft(32, '0'));

      expect(sig.R.toRadixString(16).padLeft(32, '0'),
          'f3aa5bcc0e9f3f629c89830aed5aafa268e17a649c2535db86dfe23337123498');
      expect(sig.S.toRadixString(16).padLeft(32, '0'),
          'abad44d88d91e2925086372e703dbbbf4fd5834f2879e14cc25e0dc8a9f7629c');

      var result = verify(pub, hash, sig);
      expect(result, isTrue);
    });

    test('Usage Correctness', () {
      var ec = getP256();
      var priv = PrivateKey.fromHex(ec,
          '4c8e823461ed83b496725392415f464712c3e4fbc41607a71768c9eee44cc409');
      var pub = priv.publicKey;
      print(priv);
      print(pub);
      expect(
          pub.toHex(),
          equals(
              '0429f450662ffd20c691c09c8be4c8ef09d37f913361eecd9ae3b55878dff7fa6c8f69dc9734966ca6d5e2be79795e61c916af9e9055f0f7dbebcd0e640e896a05'));
      var hashHex =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      var hash = List<int>.generate(hashHex.length ~/ 2,
          (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
      var sig = Signature.fromASN1Hex(
          '3046022100971af75671f724de0926e10e08206ad61d25c31ba1d81a64230c30b6c04c83a7022100905399ceef8c8653d6cb115efcf9a0506feb2f426b8fb2ac54c8a91beb29b82b');

      expect(verify(pub, hash, sig), isTrue);
    });

    test('Test hashToInt', () {
      var ec = getP256();
      var hashHex =
          'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
      var hash = List<int>.generate(hashHex.length ~/ 2,
          (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));

      expect(hashToInt(hash, ec).toString(),
          '83814198383102558219731078260892729932246618004265700685467928187377105751529');
    });
  });
}
