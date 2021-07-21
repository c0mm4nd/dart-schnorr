/// Package schnorr implements the Schnorr signature, which is a digital signature
/// produced by the Schnorr signature algorithm that was described by Claus Schnorr
///
/// The code is based upon the initial proposal of Pieter Wuille when it didn't have
/// a BIP number assigned yet.
///
/// Support all curves in [elliptic package](https://pub.dev/packages/elliptic)
library schnorr;

export 'src/signature.dart';
export 'src/err.dart';
