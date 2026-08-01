## 0.0.3

- **SECURITY**: remove `print()` calls in `deterministicSign` that leaked the
  secret nonce and intermediate values to stdout.
- **SECURITY**: fix `highestFactorsOf2`, which returned 0 for exact powers of
  two and corrupted the `jacobi` symbol used by `verify()` (residuosity) and
  `getK()` (signing nonce parity).
- Fix `batchVerify`: return the real result (was always `false`), select the
  Jacobi-1 root for `R`, validate `R` is on-curve, and encode `(a*e) mod n`
  correctly.
- Fix `deterministicGetRandA`: uniform coefficient in `[1, n-1]`
  (`nextInt(1)` always returned 0); reuse a single `Random.secure()`.
- Fix `hashToInt` to apply the excess right-shift (was a no-op).
- Require `elliptic` 0.4.x for constant-time (Montgomery-ladder) scalar
  multiplication.
- Add a comprehensive test suite (33 tests).

## 0.0.2

- Update doc

## 0.0.1

- Initial version.
- Pass test cases based on S256
