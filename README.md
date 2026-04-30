# Keycloak: Have I Been Pwned Password Policy

> Reject passwords found in the [Have I Been Pwned](https://haveibeenpwned.com/)
> breach corpus, with k-anonymity privacy.

A Keycloak password-policy SPI extension that checks each new password against
the HIBP breach database. The full password and full hash never leave Keycloak,
only the first five hex characters of the SHA-1 are sent to the HIBP range API.

## What it does

Adds a password policy named **Pwned Passwords** to Keycloak's per-realm policy
list. When a user sets or changes a password, the policy:

1. Computes the SHA-1 of the password locally.
2. Sends the first 5 hex characters to
   `https://api.pwnedpasswords.com/range/{prefix}`.
3. Receives ~500-1000 hash suffixes that share the prefix, with their breach
   counts.
4. Looks up the password's own suffix locally and compares the count to the
   realm-configured threshold.
5. Rejects the password if the breach count is greater than or equal to
   threshold.

The threshold is an integer per realm; default is 1 (reject any password ever
seen in a breach).

## How it works

- **k-anonymity:** the HIBP server only learns the first 5 hex chars of the
  hash. At least ~500 candidate passwords share any given prefix, so the server
  cannot identify which password was checked.
- **Padding header:** requests include `Add-Padding: true` so the response size
  does not leak how many breach records actually matched.
- **Fail-open:** if the HIBP API is unreachable (network error, timeout, non-200
  status), the policy logs a warning and allows the password. Rationale: an
  upstream outage must not block all password changes.
- **Fail-closed on missing SHA-1:** the JVM is required to provide SHA-1; the
  unlikely absence is reported as a policy error rather than silently allowed.

## Requirements

- Keycloak **26.6.1** or compatible
- JDK **21** to build (the deployed JAR runs on Keycloak's bundled JDK)
- Outbound HTTPS access from Keycloak to `api.pwnedpasswords.com`

## Installation

Build the JAR:

```sh
./mvnw clean package
```

Drop it into your Keycloak `providers/` directory and rebuild:

```sh
cp target/keycloak-pwned-password-policy-*.jar "$KC_HOME/providers/"
"$KC_HOME/bin/kc.sh" build
```

Restart Keycloak. The SPI auto-discovers via
`META-INF/services/org.keycloak.policy.PasswordPolicyProviderFactory`.

### Docker (sample)

A reference `Dockerfile` and Compose file live in [`docker/`](docker/) - they
build the JAR and produce a Keycloak image with the policy preloaded. See
[`docker/README.md`](docker/README.md) for usage. Samples only; not a
production-ready image.

Pre-built artifacts will be published on the project's Codeberg releases page
(when available) and/or Maven Central.

## Configuration

1. Open the Keycloak Admin Console and select your realm.
2. Navigate to **Authentication -> Policies -> Password Policy**.
3. Click **Add policy** and choose **Pwned Passwords**.
4. Set the integer threshold:
   - `1` (default) - reject any password ever recorded in a breach.
   - `N > 1` - allow passwords whose breach count is strictly less than `N`.
     Useful for phased rollouts where you want to block the worst offenders
     without locking out users on mildly common passwords.

Only one instance of this policy is supported per realm.

## Custom error messages (i18n)

Override these message keys in your Keycloak theme's
`messages_<locale>.properties`:

| Key                                           | When it fires                                                  | Format args       |
| --------------------------------------------- | -------------------------------------------------------------- | ----------------- |
| `invalidPasswordPwnedPasswordBreachedMessage` | Password's breach count meets or exceeds the threshold.        | `{0}` = threshold |
| `invalidPasswordPwnedNoSuchAlgorithmMessage`  | JVM does not provide SHA-1 (effectively never on a stock JDK). | none              |

Example English defaults you might supply:

```properties
invalidPasswordPwnedPasswordBreachedMessage=This password has appeared in {0} or more known data breaches. Please choose a different one.
invalidPasswordPwnedNoSuchAlgorithmMessage=Password could not be checked against the breach database. Contact your administrator.
```

## Privacy & security notes

- Full SHA-1 hash and full password never leave Keycloak - only the 5-char
  prefix is sent.
- The HIBP server cannot determine which exact password was checked.
- The `Add-Padding: true` header mitigates response-size correlation attacks
  against TLS metadata observers.
- Logs include only the upstream error message, never the password, the full
  hash, or the prefix.

## Build from source

```sh
./mvnw clean package           # JAR in target/
./mvnw test                    # unit tests
./mvnw org.pitest:pitest-maven:mutationCoverage   # mutation report in target/pit-reports/
```

Java 21 toolchain is required.

## Project layout

```
src/main/java/net/rishvic/keycloak/policy/
  BreachedPasswordLookup.java              # interface: SHA-1 hash -> breach count
  HibpHttpClient.java                      # HIBP impl + static response parser
  PwnedPasswordPolicyProvider.java         # hash + threshold-compare logic
  PwnedPasswordPolicyProviderFactory.java  # Keycloak SPI factory wiring
src/main/resources/META-INF/services/      # SPI registration descriptor
src/test/java/...                          # JUnit 5 + AssertJ unit tests
```

## Limitations

- Each password validation makes one HTTPS round-trip to HIBP. There is no cache
  yet; planned.
- Fails open on network errors. Operators who require fail-closed semantics will
  need a future config flag.
- HIBP rate limits are not handled explicitly. The range API has no documented
  rate limit at time of writing - verify current HIBP terms before high-volume
  deployments.

## Roadmap

- Prefix-keyed cache to cut redundant HTTP calls.
- Configurable fail-open vs fail-closed behavior.

## Contributing

Issues and pull requests are welcome on Codeberg. Run `./mvnw test` before
submitting. By contributing you agree to license your work under Apache License
2.0; see `LICENSE` and `NOTICE`.

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) by Troy Hunt - for the breach
  corpus and free range API.
- HIBP
  [Pwned Passwords range API documentation](https://haveibeenpwned.com/api/v3#PwnedPasswords).
