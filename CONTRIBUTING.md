# Contributor guide

[![GitLab Pipeline Status](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/pipeline.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/pipelines)
[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=main)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=main)

Follow this steps to run/debug/develop the application on your machine.

For an environment, look at [operations.md](docs/operations.md).

## Design

The application source code is in the following .NET projects:

Project name               | Technology | Project type
---------------------------|------------|------------------------------
`BlazorApp`                | ASP.NET 10 | Blazor Server web application
`Common.System`            | .NET 10    | Library
`Domain`                   | .NET 10    | Library
`Infrastructure.MongoDb`   | .NET 10    | Library
`WebApi`                   | ASP.NET 10 | Web application (REST API)
`WebApi.Contracts`         | .NET 10    | Library

The application is using the following .NET packages (via NuGet):

Name                | Description
--------------------|--------------------
`FirebaseAdmin`     | Firebase
`MongoDB.Bson`      | MongoDB BSON
`MongoDB.Driver`    | MongoDB .NET Driver
`Scalar.AspNetCore` | OpenAPI web UI

## Requirements

1. [.NET 10.0 SDK](https://dotnet.microsoft.com/download)

2. MongoDB database

    Several options:

    - Local server
  
    ```bash
    cd D:/Programs/mongodb-8.2/bin
    md log
    md data
    mongod --logpath log/mongod.log --dbpath data --port 27017
    ```
  
    - [Docker](https://hub.docker.com/_/mongo/)
  
    ```bash
    docker run --name mongodb -d -p 27017:27017 mongo:8.2
    ```
  
    - [MongoDB Atlas](https://cloud.mongodb.com/) cluster

3. IDE: Rider, Visual Studio, Visual Studio Code

## Configuration

### Web API settings

Key                                       | Description
------------------------------------------|--------------------------
`Infrastructure:MongoDB:ConnectionString` | MongoDB connection string
`Infrastructure:MongoDB:DatabaseName`     | MongoDB database name

This values can be easily provided as environment variables (replace ":" by "__") or by configuration (json).

Template for `src/WebApi/appsettings.Development.json`:

```json
{
  "AllowedOrigins": [
    "http://localhost:5207",
    "https://localhost:7042"
  ],
  "Authentication": {
    "JwtBearer": {
      "Authority": "https://securetoken.google.com/<firebase-project-id>",
      "TokenValidation": {
        "Issuer": "https://securetoken.google.com/<firebase-project-id>",
        "Audience": "<firebase-project-id>"
      }
    }
  },
  "Features": {
    "IsScalarEnabled": true,
    "IsHttpsRedirectionEnabled": false
  },
  "Infrastructure": {
    "MongoDB": {
      "ConnectionString": "mongodb://localhost:27017",
      "DatabaseName": "keeptrack_dev"
    }
  },
  "Logging": {
    "LogLevel": {
      "Default": "Debug",
      "KeepTrack": "Debug"
    }
  }
}
```

### Blazor Server App settings

Key                                     | Required | Default value
----------------------------------------|----------|--------------
AllowedHosts                            | false    | "*"
Features:IsHttpsRedirectionEnabled      | false    | true
Firebase:WebAppConfiguration:ApiKey     | true     | ""
Firebase:WebAppConfiguration:AuthDomain | true     | ""
Firebase:WebAppConfiguration:ProjectId  | true     | ""
Firebase:ServiceAccount                 | true     | ""
Logging:LogLevel:Default                | false    | "Information"
Logging:LogLevel:Microsoft.AspNetCore   | false    | "Warning"
WebApi:BaseUrl                          | true     | ""

## Run

```bash
dotnet restore

dotnet build

# run the API (https://localhost:5011/)
dotnet run --project src/WebApi

# run the Blazor WebAssembly web app (https://localhost:5021)
dotnet run --project src/BlazorApp
```

## Tests

The solution has two test projects:

- `test/WebApi.UnitTests` has no external dependencies.
- `test/WebApi.IntegrationTests` needs a running MongoDB and a Firebase test user, since it boots the real Web API and calls it like a real client would.

Run everything:

```bash
dotnet test
```

Run just one project:

```bash
dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj
```

Run a single test by fully qualified name (works for either project):

```bash
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.MappingProfiles.AutoMapperConfigurationTest.WebApiAutoMapperProfile_ShouldBeValid"
```

### Unit tests

No configuration needed - `dotnet test test/WebApi.UnitTests/WebApi.UnitTests.csproj` works as soon as the solution restores.

### Integration tests

These need two things configured before they'll pass:

1. **A MongoDB instance** (see [Requirements](#requirements) above), pointed at by `Infrastructure__MongoDB__ConnectionString`/`Infrastructure__MongoDB__DatabaseName`.
   Use a dedicated database (e.g. `keeptrack_integrationtests`), not your dev database - tests create and delete real documents.
   Running `scripts/mongodb-create-index.js` against it first is recommended (keeps behavior closest to production) but not required for the tests themselves to pass.
2. **A Firebase test user**, since `ResourceTestBase.Authenticate()` performs a real Firebase sign-in to obtain a bearer token:
   - `FIREBASE_APIKEY`: the Firebase project's Web API key (Firebase Console → Project settings → General → Web API Key).
   - `FIREBASE_USERNAME` / `FIREBASE_PASSWORD`: the email/password of a real user created in that project (Firebase Console → Authentication → Users → Add user).
     Use a dedicated test account, not a personal one.
   - `Authentication__JwtBearer__Authority`, `..__TokenValidation__Issuer`, `..__TokenValidation__Audience`: all `https://securetoken.google.com/<firebase-project-id>`.
     See the [Web API settings](#web-api-settings) above for the Issuer/Audience split.
     This is what lets the API-under-test validate the token issued by that same Firebase project.

Provide all of this as environment variables (works everywhere, including CI - see `.github/workflows/ci.yaml` for how the pipeline supplies its own test account), for example:

```bash
export AllowedOrigins__0=http://localhost:5207
export Infrastructure__MongoDB__ConnectionString=mongodb://localhost:27017
export Infrastructure__MongoDB__DatabaseName=keeptrack_integrationtests
export Authentication__JwtBearer__Authority=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Issuer=https://securetoken.google.com/<firebase-project-id>
export Authentication__JwtBearer__TokenValidation__Audience=<firebase-project-id>
export FIREBASE_APIKEY=<web-api-key>
export FIREBASE_USERNAME=<test-user-email>
export FIREBASE_PASSWORD=<test-user-password>

dotnet test test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj
```

Or, for an IDE-driven workflow, put the same values in a `Local.runsettings` file at the repository root (gitignored - never commit it) so Rider/Visual Studio pick them up automatically for test runs:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <AllowedOrigins__0>http://localhost:5207</AllowedOrigins__0>
      <Infrastructure__MongoDB__ConnectionString>mongodb://localhost:27017</Infrastructure__MongoDB__ConnectionString>
      <Infrastructure__MongoDB__DatabaseName>keeptrack_integrationtests</Infrastructure__MongoDB__DatabaseName>
      <Authentication__JwtBearer__Authority></Authentication__JwtBearer__Authority>
      <Authentication__JwtBearer__TokenValidation__Issuer></Authentication__JwtBearer__TokenValidation__Issuer>
      <Authentication__JwtBearer__TokenValidation__Audience></Authentication__JwtBearer__TokenValidation__Audience>
      <!-- <KESTREL_WEBAPP_URL>xxxx</KESTREL_WEBAPP_URL> -->
      <FIREBASE_APIKEY>xxxx</FIREBASE_APIKEY>
      <FIREBASE_USERNAME>xxxx</FIREBASE_USERNAME>
      <FIREBASE_PASSWORD>xxxx</FIREBASE_PASSWORD>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

Or in Rider, in "File | Settings | Build, Execution, Deployment | Unit Testing | Test Runner", set the same three Firebase variables directly so they apply to every test run in the IDE without a file.

Set `KESTREL_WEBAPP_URL` to target a specific already-running instance instead of letting the tests spin up their own.

## Container images

```bash
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```
