# Configuration

Settings come from `appsettings.json`, then `appsettings.Development.json` (gitignored), then environment variables, where `:` becomes `__`.
[Open src/WebApi/appsettings.json](:open:src/WebApi/appsettings.json) and [open src/BlazorApp/appsettings.json](:open:src/BlazorApp/appsettings.json): every value is a default, and the secrets are empty.

This lab uses environment variables, as the "Without Firebase" section of `CONTRIBUTING.md` does, written to `~/.bashrc` so every new shell has them.

## Local authentication

`BlazorApp` signs a token for the user, and `WebApi` checks it with the same key, so the two share one.
The issuer and the audience are the same on both sides too.

1. Generate the key, and declare the authentication of both applications:

   ```bash exec
   KEY=$(openssl rand -base64 32) && \
   cat >> ~/.bashrc <<EOT
   # Keeptrack WebApi: validates tokens signed with the shared key, instead of a Firebase authority
   export Authentication__JwtBearer__Authority=
   export Authentication__JwtBearer__SigningKey="${KEY}"
   export Authentication__JwtBearer__TokenValidation__Issuer=keeptrack-local
   export Authentication__JwtBearer__TokenValidation__Audience=keeptrack-local
   # Keeptrack BlazorApp: signs users in with a form, and their tokens with the shared key
   export Authentication__Mode=Local
   export Authentication__Local__SigningKey="${KEY}"
   export Authentication__Local__Issuer=keeptrack-local
   export Authentication__Local__Audience=keeptrack-local
   EOT
   ```

   > [!NOTE]
   > The key is base64 and decodes to at least 32 bytes, as HS256 needs, and both applications check it when they start.
   > Anyone holding it can sign a token for any account, so it stays on the machine.

## The rest

1. Declare the database, the URLs of the applications, the API documentation, and plain HTTP:

   ```bash exec
   cat >> ~/.bashrc <<EOT
   # Keeptrack WebApi
   export Infrastructure__MongoDB__ConnectionString=mongodb://localhost:27017
   export Infrastructure__MongoDB__DatabaseName=keeptrack_dev
   export AllowedOrigins__0=${BLAZORAPP_URL}
   export Features__IsScalarEnabled=true
   # Keeptrack BlazorApp
   export WebApi__BaseUrl=${WEBAPI_URL}
   # Both, since the lab serves them over HTTP on localhost only
   export Features__IsHttpsRedirectionEnabled=false
   EOT
   ```

2. Map the reference data providers the lab was given, by name, so their values never land in a file:

   ```bash exec
   cat >> ~/.bashrc <<'EOT'
   # Keeptrack WebApi: reference data providers, each one skipped when its value is empty
   export Tmdb__ApiKey="${TMDB_APIKEY:-}"
   export Omdb__ApiKey="${OMDB_APIKEY:-}"
   export Igdb__ClientId="${IGDB_CLIENTID:-}"
   export Igdb__ClientSecret="${IGDB_CLIENTSECRET:-}"
   export Rawg__ApiKey="${RAWG_APIKEY:-}"
   export Discogs__Token="${DISCOGS_TOKEN:-}"
   export GoogleBooks__ApiKey="${GOOGLEBOOKS_APIKEY:-}"
   EOT
   ```

   > [!NOTE]
   > The quoted `'EOT'` keeps `${TMDB_APIKEY:-}` as it is written, so the shell reads the value at each start.
   > `CONTRIBUTING.md` lists where each provider issues its key.

3. Load the file, and list what the applications will read, the secrets masked:

   <!-- verify: expect="Authentication__Mode=Local" -->

   ```bash exec
   . ~/.bashrc && \
   env | grep -E '^(Authentication|Infrastructure|AllowedOrigins|Features|WebApi|Tmdb|Omdb|Igdb|Rawg|Discogs|GoogleBooks)_' | sed -E 's/((Key|Secret|Token|Id)=).+/\1***/' | sort
   ```

## Local refused in Production

1. Start `BlazorApp` as it would run in production, and read why it stops:

   <!-- verify: timeout=180 expect="refused in the Production environment" -->

   ```bash exec
   cd ~/keeptrack && \
   ASPNETCORE_ENVIRONMENT=Production dotnet run --project src/BlazorApp --no-build --no-launch-profile 2>&1 | grep -m 1 'Authentication:Mode'
   ```

   `ASPNETCORE_ENVIRONMENT` is `Production` when it is not set, so local authentication only runs where an environment is named on purpose.
   The next step runs both applications with the `http` profile of their `Properties/launchSettings.json`, which sets `Development`.
