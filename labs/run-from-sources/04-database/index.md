# Database

## Start MongoDB

1. Start `mongod` in the background, with its data in the home directory, listening on the loopback only:

   <!-- verify: timeout=60 expect="child process started successfully" -->

   ```bash exec
   mkdir -p ~/mongodb/data && \
   mongod --dbpath ~/mongodb/data --bind_ip 127.0.0.1 --fork --logpath ~/mongodb/mongod.log
   ```

   > [!NOTE]
   > `--fork` returns once the server accepts connections, so the next command needs no wait.
   > The container has no init system, so a new lab session starts it again with the same command.

2. Check it answers:

   <!-- verify: expect="ok: 1" -->

   ```bash exec
   mongosh --quiet mongodb://localhost:27017 --eval 'db.runCommand({ ping: 1 })'
   ```

## Indexes

The applications never create indexes themselves.
[Open scripts/mongodb-create-index.js](:open:scripts/mongodb-create-index.js): one idempotent script, re-run after every change to it.

1. Create them in `keeptrack_dev`, the database the applications use in this lab:

   <!-- verify: expect="movie_owner" -->

   ```bash exec
   cd ~/keeptrack && \
   mongosh --quiet "mongodb://localhost:27017/keeptrack_dev" scripts/mongodb-create-index.js && \
   mongosh --quiet "mongodb://localhost:27017/keeptrack_dev" --eval 'db.movie.getIndexes().map(i => i.name)'
   ```

## Integration tests

Integration tests host `WebApi` in the test process, against a real MongoDB.
Without Firebase variables, they sign in with local authentication: a signing key is generated for the run and tokens are minted directly.

1. Run the ones that prove a locally signed token is accepted, one signed with another key refused, and each role held to its tier:

   <!-- verify: timeout=600 expect="failed: 0" -->

   ```bash exec
   TEST_AUTHENTICATION_MODE=local \
   Infrastructure__MongoDB__ConnectionString=mongodb://localhost:27017 \
   Infrastructure__MongoDB__DatabaseName=keeptrack_integrationtests \
   AllowedOrigins__0=http://localhost \
   dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --no-build --filter-method "*LocalAuthenticationResourceTest*"
   ```

   > [!NOTE]
   > The suite refuses a database named like a real one, `keeptrack_dev` included, so it is given a throwaway one, which it leaves as it found it.
   > `WebApi` refuses to start without at least one CORS origin in `AllowedOrigins`, the hosted one included, whatever its value.
