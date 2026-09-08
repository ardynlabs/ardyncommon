# Ardyn Common

`github.com/ardynlabs/ardyncommon` is the small, shared Go 1.23 platform
library for Ardyn services. It contains cross-cutting contracts only; it has no
Citizen or other domain models, no database access, and no concrete Kafka
client. Services remain independently deployable and communicate with other
services exclusively through Kafka.

## Packages

- `config` loads one YAML configuration document strictly. Unknown fields and
  multiple documents fail fast.
- `auth` is transport-neutral RS256 JWT signing and verification. It keeps
  parsed RSA keys in memory, requires issuer/audience/expiry validation, and
  rejects every algorithm except exactly RS256.
- `ginauth` is the optional Gin adapter for `auth.Verifier`. It safely parses
  Bearer credentials, returns 401 for authentication failures and 403 for role
  failures, and stores typed claims in Gin context.
- `api` exposes generic successful-response and RFC 9457 problem-details
  models.
- `messaging` defines the versioned JSON event envelope, correlation metadata,
  and publisher/consumer interfaces that a service-owned Kafka adapter
  implements.
- `banner` writes the shared Ardyn startup logo to an `io.Writer`.

## JWT usage

Load PEM files during startup with `auth.LoadRSAPrivateKeyFile` and
`auth.LoadRSAPublicKeyFile`, then create a manager with an explicit issuer and
audience. A manager may be signing-only, verification-only, or both. The
private key is never exposed as PEM bytes after loading.

```go
privateKey, _ := auth.LoadRSAPrivateKeyFile("/run/secrets/jwt-private.pem")
publicKey, _ := auth.LoadRSAPublicKeyFile("/run/secrets/jwt-public.pem")
tokens, _ := auth.New(privateKey, publicKey, "ardyn-identity", "ardyn-api")
```

## Breaking migration from the legacy library

All legacy packages (`ardynconfig`, `ardynjwt`, `ardynmiddleware`,
`ardynstructs`, and `ardynlogo`) were removed and are intentionally not source
compatible. Migrate imports to the packages above. In particular, replace the
old untyped JWT API with `auth.Manager`, and replace direct Gin assumptions in
JWT code with `ginauth` middleware.

`ardynwatcher` was removed completely, as was its `fsnotify` dependency. Do
not add an in-process file watcher: Kubernetes configuration deployment and
reload/restart policy owns that responsibility.
