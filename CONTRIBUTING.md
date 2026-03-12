# Contributor guide

[![GitLab Pipeline Status](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/pipeline.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/pipelines)
[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=main)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=main)

Follow this steps to run/debug/develop the application on your machine.

For an environment, look at [operations.md](docs/operations.md).

## Design

NuGet Packages:

- [MongoDB C# Driver](https://www.mongodb.com/docs/drivers/csharp/current/)

## Requirements

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download)
- MongoDB database (up to 8.2)
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

## How to configure

### Web API

Key                                       | Description
------------------------------------------|--------------------------
`Infrastructure:MongoDB:ConnectionString` | MongoDB connection string
`Infrastructure:MongoDB:DatabaseName`     | MongoDB database name

This values can be easily provided as environment variables (replace ":" by "__") or by configuration (json).

Template for `src/Api/appsettings.Development.json`:

```json
{
  "Authentication": {
    "JwtBearer": {
      "Authority": "https://securetoken.google.com/<firebase-project-id>",
      "TokenValidation": {
        "Issuer": "https://securetoken.google.com/<firebase-project-id>",
        "Audience": "<firebase-project-id>"
      }
    }
  },
  "Infrastructure": {
    "MongoDB": {
      "ConnectionString": "mongodb://localhost:27017",
      "DatabaseName": "keeptrack"
    }
  },
  "Logging": {
    "LogLevel": {
      "KeepTrack": "Debug",
      "Withywoods": "Debug"
    }
  }
}
```

### Blazor Server App

TODO

## How to build

```bash
dotnet restore
dotnet build
```

## How to debug

```bash
# run the API (https://localhost:5011/)
dotnet run --project src/WebApi

# run the Blazor WebAssembly web app (https://localhost:5021)
dotnet run --project src/BlazorApp
```

## How to test

For integration tests, to manage the configuration (secrets) you can create a file at the root directory called `Local.runsettings` or define them as environment variables:

```xml
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <AllowedOrigins__0>http://localhost:4200</AllowedOrigins__0>
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

Or in Rider, in "File | Settings | Build, Execution, Deployment | Unit Testing | Test Runner"

- FIREBASE_APIKEY
- FIREBASE_USERNAME
- FIREBASE_PASSWORD

Set KESTREL_WEBAPP_URL to target a specific instance (not use web app test instance).

And execute all tests (unit and integration ones):

```bash
dotnet test --settings Local.runsettings
```
