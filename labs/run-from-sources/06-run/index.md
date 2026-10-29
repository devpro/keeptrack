# Run

Each application runs with the `http` profile of its `Properties/launchSettings.json`, as an IDE does: the `Development` environment, and a fixed port.
[Open src/WebApi/Properties/launchSettings.json](:open:src/WebApi/Properties/launchSettings.json) to see one.

## WebApi

1. Start it in the background, and wait until its health check answers:

   <!-- verify: timeout=180 expect="Healthy" -->

   ```bash exec
   cd ~/keeptrack && \
   nohup dotnet run --project src/WebApi --launch-profile http --no-build > ~/webapi.log 2>&1 &
   wget -qO- --retry-connrefused --tries=120 --waitretry=1 "${WEBAPI_URL}/healthz"; echo
   ```

   > [!NOTE]
   > `/healthz` also checks MongoDB, so `Healthy` means the API reaches the database.
   > `nohup` keeps the process running once this terminal is closed, and its output goes to `~/webapi.log`.

2. Call an endpoint without a token, which the API refuses:

   <!-- verify: expect="HTTP/1.1 401" -->

   ```bash exec
   wget -S -O /dev/null "${WEBAPI_URL}/api/movies" 2>&1 | grep 'HTTP/'
   ```

3. [Open the API reference](:navigate:api:http://localhost:5057/scalar) in the lab browser: Scalar, generated from the OpenAPI description and the XML comments of the controllers.

## BlazorApp

1. Start it in the background, and wait until it answers:

   <!-- verify: timeout=180 expect="Healthy" -->

   ```bash exec
   cd ~/keeptrack && \
   nohup dotnet run --project src/BlazorApp --launch-profile http --no-build > ~/blazorapp.log 2>&1 &
   wget -qO- --retry-connrefused --tries=120 --waitretry=1 "${BLAZORAPP_URL}/healthz"; echo
   ```

2. Check the login page offers the local form, rather than the GitHub and Google buttons:

   <!-- verify: expect="Local sign-in, for test environments only." -->

   ```bash exec
   wget -qO- "${BLAZORAPP_URL}/account/login" | grep -o 'Local sign-in[^<]*'
   ```

3. [Open Keeptrack](:navigate:app:http://localhost:5207/) in the lab browser.

> [!TIP]
> Both logs are in the home directory: `tail -f ~/webapi.log ~/blazorapp.log` follows them.
> `pkill -f 'dotnet run'` stops both applications.
