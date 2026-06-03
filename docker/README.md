# Docker samples

Reference Docker assets that build the SPI from source and produce a Keycloak
image with the **Pwned Passwords** policy preloaded.

> **Samples only.** These files are intended for local evaluation and
> integration testing. They are not a production-ready image - see the
> [Caveats](#caveats) section below.

## What's here

| File           | Purpose                                                                 |
| -------------- | ----------------------------------------------------------------------- |
| `Dockerfile`   | Multi-stage build: Maven builder stage -> Keycloak final stage with JAR |
| `compose.yaml` | One-service stack to run the resulting image with `start-dev`           |

## Build (standalone)

Run from the **repository root** (build context is `.`, not `docker/`):

```sh
docker build -f docker/Dockerfile -t keycloak-hibp:dev .
```

## Run (standalone)

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  keycloak-hibp:dev start-dev
```

## Run (Compose)

```sh
docker compose -f docker/compose.yaml up --build
```

`compose.yaml` declares `context: ..`, so it must be invoked with the path shown
above (or from inside `docker/` with `docker compose up --build`).

Tear down:

```sh
docker compose -f docker/compose.yaml down
```

## Verify

1. Open `http://localhost:8080` and log in with `admin` / `admin`.
2. Select a realm (the default `master` is fine for a smoke test).
3. Navigate to **Authentication -> Policies -> Password Policy**.
4. Click **Add policy** - the dropdown should list **Pwned Passwords**.
5. Add it with threshold `1`, save.
6. Create a test user and try setting their password to a known-pwned value such
   as `Password1`. The change should be rejected with the breach message.
7. Boot logs should include a line referencing
   `PwnedPasswordPolicyProviderFactory` registering at startup.

## Build args

| Arg                | Default                     | Purpose                                          |
| ------------------ | --------------------------- | ------------------------------------------------ |
| `KEYCLOAK_VERSION` | `26.6.2`                    | Keycloak base image tag and `-Dkeycloak.version` |
| `MAVEN_IMAGE`      | `3.9.15-eclipse-temurin-21` | Builder stage base (`maven:${MAVEN_IMAGE}`)      |

Override at build time, for example to test against a newer Keycloak release:

```sh
docker build -f docker/Dockerfile \
  --build-arg KEYCLOAK_VERSION=26.6.2 \
  -t keycloak-hibp:pinned .
```

The compose file pins `KEYCLOAK_VERSION` under `services.keycloak.build.args`;
edit it there if you want the Compose stack to track a different release.

## Caveats

- **Ephemeral state.** `start-dev` uses an in-memory H2 database. Realm
  configuration, users, and credentials are wiped when the container is removed.
  Mount a volume on `/opt/keycloak/data` if you need persistence across
  restarts.
- **No production DB.** `kc.sh build` runs without `--db=...`, so the image is
  not optimized for Postgres, MySQL, or any external database. For a real
  deployment, add the appropriate `--db=...` flag to the `RUN` line and
  configure `KC_DB_*` environment variables at runtime.
- **Dummy admin credentials.** `admin` / `admin` is acceptable only for local
  evaluation. Never reuse on any reachable host.
- **Dev-mode HTTP.** `start-dev` serves plain HTTP on `8080`. Production
  requires HTTPS; see Keycloak's
  [Configuring TLS](https://www.keycloak.org/server/enabletls) docs.
- **Image size.** ~700 MB, dominated by the Keycloak base. Only the SPI JAR (~10
  KB) is added on top.

## Troubleshooting

- **`Bind for 0.0.0.0:8080 failed: port is already allocated`** - another
  process holds `8080`. Remap with `-p 8081:8080` or stop the conflicting
  service.
- **Builder stage fails pulling `maven:...`** - the `MAVEN_IMAGE` tag may not
  exist on Docker Hub. Verify with
  `docker manifest inspect maven:${MAVEN_IMAGE}` and adjust the build arg.
- **`Unable to find image quay.io/keycloak/keycloak:...`** - `KEYCLOAK_VERSION`
  must match a real upstream tag at `quay.io/keycloak/keycloak`.
- **Pwned Passwords missing from policy dropdown** - check container logs for
  errors loading `PwnedPasswordPolicyProviderFactory`. A common cause is
  forgetting to rebuild the image after editing the JAR.
- **Password changes silently accepted despite a breached password** - the
  policy fails open on HIBP API errors by design (see root README). Check
  outbound HTTPS to `api.pwnedpasswords.com` from inside the container:
  `docker exec <id> curl -sI https://api.pwnedpasswords.com/range/00000`.
