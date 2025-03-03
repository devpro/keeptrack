# Keeptrack .NET solution

[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=master)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=master)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=devpro.keep-track&metric=alert_status)](https://sonarcloud.io/dashboard?id=devpro.keep-track)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=devpro.keep-track&metric=coverage)](https://sonarcloud.io/dashboard?id=devpro.keep-track)

## Design

This design of API has been inspired by the [Hexagonal Architecture](https://blog.octo.com/en/hexagonal-architecture-three-principles-and-an-implementation-example/).

NuGet Packages:

- [MongoDB C# Driver](https://www.mongodb.com/docs/drivers/csharp/current/)

## Requirements

- [.NET 9.0 SDK](dot.net)
- MongoDB 8.0 database
  - Local server

  ```bash
  cd D:/Programs/mongodb-8.0/bin
  md log
  md data
  mongod --logpath log/mongod.log --dbpath data --port 27017
  ```

  - [Docker](https://hub.docker.com/_/mongo/)

  ```bash
  docker run --name mongodb80 -d -p 27017:27017 mongo:8.0
  ```

  - [MongoDB Atlas](https://cloud.mongodb.com/) cluster

  - Database indexes

  ```bash
  docker run --rm --link mongodb -v "$(pwd)/scripts":/home/scripts mongo:8.0 bash -c "mongo mongodb://mongodb:27017/keeptrack /home/scripts/mongo-create-index.js"
  ```

## How to configure

### API

Key                                       | Description               | Default value
----------------------------------------- | ------------------------- | -------------
`Infrastructure:MongoDB:ConnectionString` | MongoDB connection string |
`Infrastructure:MongoDB:DatabaseName`     | MongoDB connection string | inventory

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

### Blazor WebAssembly Firebase information

Create a file `firebase.config.js` in `src/BlasorWebAssemblyApp/wwwroot`:

```js
export var firebaseConfig = {
  apiKey: "******",
  authDomain: "******.firebaseapp.com",
  databaseURL: "******.firebaseio.com",
  projectId: "******",
  storageBucket: "******.appspot.com",
  messagingSenderId: "******",
  appId: "1:******:web:******",
  measurementId: "******"
};
```

## How to build

```bash
dotnet restore
dotnet build
```

## How to debug

```bash
# run the API (https://localhost:5011/)
dotnet run --project src\Api

# run the Blazor WebAssembly web app (https://localhost:5021)
dotnet watch run --project src\BlazorWebAssemblyApp
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
      <Keeptrack__Production__Url>xxxx</Keeptrack__Production__Url>
      <Firebase__Application__Key>xxxx</Firebase__Application__Key>
      <Firebase__Username>xxxx</Firebase__Username>
      <Firebase__Password>xxxx</Firebase__Password>
    </EnvironmentVariables>
  </RunConfiguration>
</RunSettings>
```

And execute all tests (unit and integration ones):

```bash
dotnet test --settings Local.runsettings
```

## How to deploy

- Add the outbout IP to the MongoDB Atlas cluster
- Add the application url to Firebase domains
- Create web project in Firebase and grab ids to be set to environment.ts file
- Create a GitHub OAuth application ([firebase.google.com](https://firebase.google.com/docs/auth/web/github-auth),
[github.com](https://github.com/settings/applications/new))
- Add urls in Azure web app CORS page

## How to operate

- Backup MongoDB database

```bash
docker run --rm -it --workdir=/data --volume $(pwd):/data mongo:8.0 /bin/sh -c "mongodump --uri mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.<PROJECT>.mongodb.net/test"
```

- Restore MongoDB database

```bash
docker run --rm -it --workdir=/data --volume $(pwd):/data mongo:8.0 /bin/sh -c "mongorestore --uri mongodb+srv://<USER>:<PASSWORD>@<CLUSTER>.<PROJECT>.mongodb.net"
```
