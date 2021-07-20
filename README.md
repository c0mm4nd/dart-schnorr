# dart-schnorr

Package schnorr implements the Schnorr signature, which is a digital signature
produced by the Schnorr signature algorithm that was described by Claus Schnorr

The code is based upon the initial proposal of Pieter Wuille when it didn't have a BIP number assigned yet.

The current version passes all test vectors provided here.
But the author does not give any guarantees that the algorithm is implemented correctly for every edge case!

Support all curves in [elliptic package](https://pub.dev/packages/elliptic)

## Usage

A simple usage example:

```dart
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
```

## Features and bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://github.com/c0mm4nd/dart-schnorr/issues
