import 'package:elliptic/elliptic.dart';
import 'package:schnorr/schnorr.dart';
import 'package:schnorr/src/utils.dart';
import 'package:test/test.dart';

class TestCase {
  late String priv;
  late String pub;
  late String m;
  late String sig;
  late bool result;
  late String error;
  late String description;
  TestCase(this.priv, this.pub, this.m, this.sig, this.result, this.error,
      this.description);
}

// commented out some curve keys test cases
var testCases = [
  TestCase(
    '0000000000000000000000000000000000000000000000000000000000000001',
    '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF67031A98831859DC34DFFEEDDA86831842CCD0079E1F92AF177F7F22CC1DCED05',
    true,
    '',
    '',
  ),
  TestCase(
    'B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    true,
    '',
    '',
  ),
  TestCase(
    'C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7',
    '03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B',
    '5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    '00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BE00880371D01766935B92D2AB4CD5C8A2A5837EC57FED7660773A05F0DE142380',
    true,
    '',
    '',
  ),
  TestCase(
    '6d6c66873739bc7bfb3526629670d0ea357e92cc4581490d62779ae15f6b787b',
    '026d7f1d87ab3bbc8bc01f95d9aece1e659d6e33c880f8efa65facf83e698bbbf7',
    'b2f0cd8ecb23c1710903f872c31b0fd37e15224af457722a87c5e0c7f50fffb3',
    '68ca1cc46f291a385e7c255562068357f964532300beadffb72dd93668c0c1cac8d26132eb3200b86d66de9c661a464c6b2293bb9a9f5b966e53ca736c7e504f',
    true,
    '',
    '',
  ),
  TestCase(
    '',
    '03DEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
    '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703',
    '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D',
    true,
    '',
    '',
  ),
  TestCase(
    '',
    '031B84C5567B126440995D3ED5AABA0565D71E1834604819FF9C17F5E9D5DD078F',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '52818579ACA59767E3291D91B76B637BEF062083284992F2D95F564CA6CB4E3530B1DA849C8E8304ADC0CFE870660334B3CFC18E825EF1DB34CFAE3DFC5D8187',
    true,
    '',
    'test fails if jacobi symbol of x(R) instead of y(R) is used',
  ),
  TestCase(
    '',
    '03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
    '570DD4CA83D4E6317B8EE6BAE83467A1BF419D0767122DE409394414B05080DCE9EE5F237CBD108EABAE1E37759AE47F8E4203DA3532EB28DB860F33D62D49BD',
    true,
    '',
    'test fails if msg is reduced',
  ),
  // TestCase(
  //   '',
  //   '03EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34',
  //   '4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703',
  //   '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D',
  //   false,
  //   'signature verification failed',
  //   'public key not on the curve',
  // ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFA16AEE06609280A19B67A24E1977E4697712B5FD2943914ECD5F730901B4AB7',
    false,
    'signature verification failed',
    'incorrect R residuosity',
  ),
  TestCase(
    '',
    '03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B',
    '5E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C',
    '00DA9B08172A9B6F0466A2DEFD817F2D7AB437E0D253CB5395A963866B3574BED092F9D860F1776A1F7412AD8A1EB50DACCC222BC8C0E26B2056DF2F273EFDEC',
    false,
    'signature verification failed',
    'negated message hash',
  ),
  TestCase(
    '',
    '0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798',
    '0000000000000000000000000000000000000000000000000000000000000000',
    '787A848E71043D280C50470E8E1532B2DD5D20EE912A45DBDD2BD1DFBF187EF68FCE5677CE7A623CB20011225797CE7A8DE1DC6CCD4F754A47DA6C600E59543C',
    false,
    'signature verification failed',
    'negated s value',
  ),
  // TestCase(
  //   '',
  //   '03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
  //   '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
  //   '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
  //   false,
  //   'signature verification failed',
  //   'negated public key',
  // ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '00000000000000000000000000000000000000000000000000000000000000009E9D01AF988B5CEDCE47221BFA9B222721F3FA408915444A4B489021DB55775F',
    false,
    'signature verification failed',
    'sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 0',
  ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '0000000000000000000000000000000000000000000000000000000000000001D37DDF0254351836D84B1BD6A795FD5D523048F298C4214D187FE4892947F728',
    false,
    'signature verification failed',
    'sG - eP is infinite. Test fails in single verification if jacobi(y(inf)) is defined as 1 and x(inf) as 1',
  ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    false,
    'signature verification failed',
    'sig[0:32] is not an X coordinate on the curve',
  ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC2F1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
    false,
    'r is larger than or equal to field size',
    'sig[0:32] is equal to field size',
  ),
  TestCase(
    '',
    '02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659',
    '243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89',
    '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1DFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141',
    false,
    's is larger than or equal to curve order',
    'sig[32:64] is equal to curve order',
  ),
  // TestCase(
  //   '',
  //   '6d6c66873739bc7bfb3526629670d0ea',
  //   'b2f0cd8ecb23c1710903f872c31b0fd37e15224af457722a87c5e0c7f50fffb3',
  //   '2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD',
  //   false,
  //   'signature verification failed',
  //   'public key is only 16 bytes',
  // ),
];

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

  group('case tests', () {
    late Curve curve;
    setUp(() {
      curve = getS256();
    });
    test('test sign', () {
      for (final tc in testCases) {
        if (tc.priv == '') {
          continue;
        }

        var d = PrivateKey.fromHex(curve, tc.priv);
        var m = List<int>.generate(
            tc.m.length ~/ 2,
            (index) =>
                int.parse(tc.m.substring(2 * index, 2 * index + 2), radix: 16));

        late Signature result;
        try {
          result = deterministicSign(d, m);
        } catch (e) {
          print(tc.priv +
              ' ' +
              tc.m +
              ' ' +
              e.toString() +
              tc.error +
              ': ' +
              tc.description);
        }

        expect(
            result.R.toRadixString(16).padLeft(64, '0') +
                result.S.toRadixString(16).padLeft(64, '0'),
            tc.sig.toLowerCase());
      }
    });

    test('test verify', () {
      for (final tc in testCases) {
        if (tc.sig ==
            '00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6302A8DC32E64E86A333F20EF56EAC9BA30B7246D6D25E22ADB8C6BE1AEB08D49D') {
          continue;
        }
        try {
          var pub = PublicKey.fromHex(curve, tc.pub);
          var m = List<int>.generate(
              tc.m.length ~/ 2,
              (index) => int.parse(tc.m.substring(2 * index, 2 * index + 2),
                  radix: 16));

          var sig = Signature.fromRS(
              BigInt.parse(tc.sig.substring(0, 64), radix: 16),
              BigInt.parse(tc.sig.substring(64, 128), radix: 16));
          var observed = verify(pub, m, sig);

          if (tc.error == '') {
            expect(observed, tc.result);
          }
        } catch (e) {
          if (tc.error == '') {
            rethrow;
          }
          expect(e, SchnorrException(tc.error));
        }
      }
    });
  });

  group('test aggregateSign', () {
    late List<PrivateKey> pks;
    late List<int> m;
    late List<AffinePoint> Ps;
    final curve = getS256();
    setUp(() {
      pks = <PrivateKey>[];
      Ps = <AffinePoint>[];

      for (final i in testCases.asMap().keys) {
        var tc = testCases[i];
        if (tc.priv == '') {
          continue;
        }
        var pk = PrivateKey.fromHex(curve, tc.priv);
        pks.add(pk);

        if (i == 0) {
          m = List<int>.generate(
              tc.m.length ~/ 2,
              (index) => int.parse(tc.m.substring(2 * index, 2 * index + 2),
                  radix: 16));
        }

        var p = curve.scalarBaseMul(pk.bytes);
        Ps.add(p);
      }
    });

    test('Can sign and verify two aggregated signatures over same message', () {
      var sig = aggregateSign(pks.sublist(0, 2), m);
      var P = curve.add(Ps[0], Ps[1]);
      var pub = marshal(curve, P);

      var observedSum = List<String>.generate(
          pub.length, (i) => pub[i].toRadixString(16).padLeft(2, '0')).join();
      var expected =
          '02bca9ea6e07a63bec3d28a00329ac3d25d2595a5f86e512142affde48a34d9a97';
      expect(observedSum, equals(expected));

      var observed = verify(PublicKey.fromPoint(curve, P), m, sig);
      expect(observed, isTrue);
    });
    test('Can sign and verify two more aggregated signatures over same message',
        () {
      var sig = aggregateSign(pks.sublist(1, 3), m);
      var P = curve.add(Ps[1], Ps[2]);
      var pub = marshal(curve, P);

      var observedSum = List<String>.generate(
          pub.length, (i) => pub[i].toRadixString(16).padLeft(2, '0')).join();
      var expected =
          '03f0a6305d39a34582ba49a78bdf38ced935b3efce1e889d6820103665f35ee45b';
      expect(observedSum, equals(expected));

      var observed = verify(PublicKey.fromPoint(curve, P), m, sig);
      expect(observed, isTrue);
    });
  });
}
