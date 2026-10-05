# Documentation

Each subject lives in one file: what the code does, why it is shaped that way, and its known gotchas.
Repository rules and conventions are in [AGENTS.md](../AGENTS.md), local setup in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Design

- [Architecture](architecture.md): projects, request flow, errors, background work, authentication, free tier, scaling.
- [Data model](data-model.md): mapping, storage conventions, MongoDB gotchas, child entities, migrations, adding a trackable type.
- [Blazor UI](blazor-ui.md): page bases, list state, rendering pitfalls, 404s, theme and icons.

## Features

- [Collections](collections.md): media, ownership, gear, collectibles, playlists, Wishlist, Watch Next, Quick Add, user preferences.
- [Journals](journals.md): car, house and health logs, their metrics and charts.
- [Sharing](sharing.md): the anonymous wishlist link and collection sharing between accounts.
- [Imports](imports.md): store and retailer transaction imports, TV Time.
- [Explore](explore.md): top-rated suggestions from provider rankings.

## Reference data

- [Reference data](reference-data.md): shared provider metadata, enrichment, ratings, sync, export and import.
- [Reference matching](reference-matching.md): aliases, what confirms a match, search policies, video game adoption.
- [Providers](providers.md): each third-party API, its quotas and its quirks.

## Running

- [Testing](testing.md): suites, databases, cleanup, end-to-end design.
- [CI and code quality](ci-and-quality.md): pipelines, IstarCI, settled Sonar findings.
- [Operations](operations.md): deployment, indexes, migrations, backups.
- [Backlog](backlog.md): known debt and gaps.
