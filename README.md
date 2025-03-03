# Keeptrack

[![GitLab Pipeline Status](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/pipeline.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/pipelines)
[![coverage report](https://gitlab.com/devpro-labs/software/keeptrack/badges/main/coverage.svg)](https://gitlab.com/devpro-labs/software/keeptrack/-/commits/main)
[![Build Status](https://dev.azure.com/devprofr/open-source/_apis/build/status/keeptrack-ci?branchName=master)](https://dev.azure.com/devprofr/open-source/_build/latest?definitionId=26&branchName=master)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=devpro.keep-track&metric=alert_status)](https://sonarcloud.io/dashboard?id=devpro.keep-track)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=devpro.keep-track&metric=coverage)](https://sonarcloud.io/dashboard?id=devpro.keep-track)

Keeptrack is a an open source application that let you save everything you read, watch, listen or play.

## Instances

This code is Cloud Native, it can be deployed to any kind of infrastructure.

A SaaS free version is currently available for early adopters (contact the repository owner to get an access).

## Software design

Application frontend is a [web application](angular-bootstrap/README.md) (Single Page Application) written in TypeScript (Angular 16+).

Application backend is a [web API](dotnet/README.md) (REST) written in C# (.NET 7+).

Application data is persisted in a MongoDB (7.0) database.

Application authentication is federated with Firebase Authentication and can be done from multiple providers (Google, GitHub, etc.).
