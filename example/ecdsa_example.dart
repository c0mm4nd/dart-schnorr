import 'package:elliptic/elliptic.dart';
import 'package:schnorr/schnorr.dart';

void main() {
  var ec = getS256();
  var priv = ec.generatePrivateKey();
  var pub = priv.publicKey;
  print(priv);
  print(pub);
  var hashHex =
      'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
  var hash = List<int>.generate(hashHex.length ~/ 2,
      (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));

  var sig = deterministicSign(priv, hash);
  var result = verify(pub, hash, sig);

  assert(result);

  var priv2 = ec.generatePrivateKey();
  var pub2 = priv.publicKey;

  var sig2 = aggregateSign([priv, priv2], hash);
  var result2 = verify(combinePublicKeys([pub, pub2]), hash, sig2);

  assert(result2);
}
