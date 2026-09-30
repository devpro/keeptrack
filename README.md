# Keeptrack

[![CI](https://github.com/devpro/keeptrack/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/devpro/keeptrack/actions/workflows/ci.yaml)
[![PKG](https://github.com/devpro/keeptrack/actions/workflows/pkg.yaml/badge.svg?branch=main)](https://github.com/devpro/keeptrack/actions/workflows/pkg.yaml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=devpro_keeptrack&metric=alert_status)](https://sonarcloud.io/dashboard?id=devpro_keeptrack)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=devpro_keeptrack&metric=coverage)](https://sonarcloud.io/dashboard?id=devpro_keeptrack)
[![Docker Image Version](https://img.shields.io/docker/v/devprofr/keeptrack-blazorapp?label=Image&logo=docker)](https://hub.docker.com/r/devprofr/keeptrack-blazorapp)

[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B60068%2Fgithub.com%2Fdevpro%2Fkeeptrack.svg?type=shield&issueType=license)](https://app.fossa.com/projects/custom%2B60068%2Fgithub.com%2Fdevpro%2Fkeeptrack?ref=badge_shield&issueType=license)
[![FOSSA Status](https://app.fossa.com/api/projects/custom%2B60068%2Fgithub.com%2Fdevpro%2Fkeeptrack.svg?type=shield&issueType=security)](https://app.fossa.com/projects/custom%2B60068%2Fgithub.com%2Fdevpro%2Fkeeptrack?ref=badge_shield&issueType=security)

Keeptrack is a source-available application to save and review everything read, watched, listened to or played.

## Hosting

The applications are cloud native and run on any container platform.
A free SaaS version is open to early adopters: contact the repository owner for access.

## Software design

Three-tier application:

- Frontend: Blazor Server application (.NET 10/C#)
- Backend: ASP.NET Web API application (.NET 10/C#)
- Database: MongoDB

Architecture and conventions are in [AGENTS.md](AGENTS.md), local setup in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Keeptrack is licensed under the [PolyForm Strict License 1.0.0](LICENSE): it is source-available, not open source.
The code may be read, run for personal noncommercial purposes, and contributed to (see [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution terms).
Any other use, in particular commercial use, distribution, or hosting the application for others, requires prior written permission from the repository owner.

Versions of this repository published before this license change remain available under their original MIT license terms.
