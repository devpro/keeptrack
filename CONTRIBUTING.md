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

### Web API appsettings

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

### Blazor Server App appsettings

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

For integration tests, to manage the configuration (secrets) you can create a file at the root directory called `Local.runsettings` or define them as environment variables:

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

Or in Rider, in "File | Settings | Build, Execution, Deployment | Unit Testing | Test Runner"

- FIREBASE_APIKEY
- FIREBASE_USERNAME
- FIREBASE_PASSWORD

Set KESTREL_WEBAPP_URL to target a specific instance (not use web app test instance).

## Container images

```bash
docker build . -t devprofr/keeptrack-blazorapp:local -f src/BlazorApp/Dockerfile
docker build . -t devprofr/keeptrack-webapi:local -f src/WebApi/Dockerfile
```
