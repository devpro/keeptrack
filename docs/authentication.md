# Authentication

How a user is identified, and how the app runs with or without Firebase.
Authorization (the `AdminOnly` and `MemberOnly` policies, the free tier) is in [Architecture](architecture.md#authentication-and-authorization).

## Modes

`BlazorApp` signs users in with one of two modes, set by `Authentication:Mode`.

Mode                 | Sign-in                                               | Use
---------------------|-------------------------------------------------------|---------------------------------------------
`Firebase` (default) | GitHub or Google through the Firebase JS SDK          | Production
`Local`              | An email and a role on a form, no password            | Isolated environments, local runs, tests

**`Local` refuses to start in the `Production` environment**, since anyone reaching the login page can sign in as anyone, admin included.
An isolated environment runs under another environment name, for example `Development` or `Test`.

A third mode for an external OpenID Connect provider (Keycloak, Zitadel, Entra) is left out until a deployment needs one.

## Coupling points

Firebase is confined to:

- `BlazorApp`: `FirebaseAuthenticationController` (`/auth/callback`, `/auth/refresh`), `FirebaseSignIn.razor`, `FirebaseSessionRefresh.razor` and the `Firebase:*` settings, all registered or rendered in `Firebase` mode only;
- the test harness: `Testing.Shared/Firebase` and the e2e fixture's ephemeral users;
- operations: `compose.yaml`, the CI secrets and `scripts/firebase-*.js`.

The rest is provider neutral:

- `WebApi` validates any JWT bearer and reads standard claims only: `sub` as the user id, `email`, `name`, and the custom `role`.
  Firebase issues `sub` equal to its uid, so stored data is unaffected by the mode.
- MongoDB holds no user store: every document carries the issuer's `sub` as `owner_id`, and share grants match on email.
  **A different issuer means different ids**, so an existing database moved to another mode keeps its data out of reach until the ids are remapped.
- `AuthenticationControllerBase` builds the cookie principal (`SessionClaimsBuilder`) and stores the API token in it, for both modes.

## Local mode

`LocalAuthenticationController` (`POST /auth/local`) mints a token with `LocalTokenIssuer` (`Common.Hosting`) and signs the user in.
The token is an HS256 JWT signed with a shared key: `BlazorApp` signs with `Authentication:Local:SigningKey`, `WebApi` validates with `Authentication:JwtBearer:SigningKey`.
Issuer and audience are configured on both sides the same way.

- The key is base64 and decodes to at least 32 bytes, checked at startup: `openssl rand -base64 32`.
- `sub` is the normalized email, so signing in again with the same email reaches the same data.
- **The token lives as long as the cookie (8h) and is never refreshed.**
  A session kept alive past that by the sliding cookie answers 401 and is sent back to login, the same path as a stale Firebase token.

`WebApi` takes either `Authority` (Firebase, or any OpenID Connect issuer) or `SigningKey`, and refuses to start with both or neither.
It reads them when the options are built, not at startup, so a test host can override them with `ConfigureAppConfiguration`.

## Tests

Every suite runs in either mode, and each mode's own code is covered in every run.

- `TestAuthentication` (`Testing.Shared`) picks the mode: `TEST_AUTHENTICATION_MODE` (`firebase` or `local`) when set, otherwise `firebase` when `FIREBASE_APIKEY` is set and `local` when it is not.
  In `local` mode it generates a signing key per run, configures the hosts with it and mints tokens directly, so no external system is reached.
- `LocalAuthenticationResourceTest` hosts `WebApi` in local mode whatever the run's mode, so token validation is proven in Firebase runs too.
- Unit tests cover `LocalTokenIssuer`, `SessionClaimsBuilder` and the controller filtering of both modes.
- The e2e suite signs in through `/auth/callback` or `/auth/local` depending on the mode, and the tests specific to one mode skip in the other.
  `BlazorApp` reads its mode before the host is built, so the fixture passes it as environment variables, like `WebApi__BaseUrl`.
