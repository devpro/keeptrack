# AGENTS.md

Guidance for coding agents working in this repository.

## Project overview

Keeptrack is source-available (PolyForm Strict 1.0.0, see `LICENSE`, not open source).
It saves and reviews everything read, watched, listened to or played: books, movies, TV shows, albums, video games, playlists, gear and collectibles, plus car, house and health journals.

Three-tier .NET 10 / C#: `BlazorApp` (Blazor Server UI), `WebApi` (ASP.NET REST API), MongoDB.

The design is described in `docs/`, starting at `docs/README.md`.

## Hard rules

**Never run a third party container image on this workstation.**
No `docker run` and no `docker pull` of any image not published by Docker or by GitHub.
Security scanners are invoked as locally installed binaries, never containerised.
A tool with no local install path is left unwired and recorded in `docs/backlog.md`.

**Linters are never run by an agent, and never imitated by hand.**
No `markdownlint`, no `yamllint`, no formatter (the owner applies `npx neatmd .` to Markdown), no `npx` invocation of any of them.
Reading a lint configuration and reshaping text to fit it, or rewrapping a paragraph so a tool would be quieter, is the same thing as running the linter.
An agent that notices prose a linter might flag says so in its report and changes nothing.
Test commands are not linters.

**Every command runs in the foreground, and the agent waits for it.**
No background command, no subagent, no fork, no parallel task, even for a long command.

**Only GitHub Actions published by `github` or `docker` are allowed in workflows.**
Reusable actions owned by this account, in `../github-workflow-parts`, are also allowed.
Anything else is replaced by an explicit command that downloads the official release binary and verifies its SHA256 checksum.

**IstarCI is recommended but optional, and runs from its package.**
The CI is the GitHub Actions pipeline, which IstarCI only runs locally first.
`task ci:setup`, `task ci` and `task ci:logs` use the installed `@devpro/istarci` package, and a clone of IstarCI is for developing IstarCI only (`task ci:from-clone`).

**The harness is Node.js and bash only.**
Python scripts or code is not allowed.

**Test before code when applicable.**
Tests are written before the implementation and versioned as the source of truth for expected behavior.
A regression test is seen failing for the stated reason before the fix, a refactor of untested code gets its test first, seen green against the unmodified code.

**Preserve existing comments and formatting when editing a file.**
Commit only when asked, and never push.

**Documentation is as short as possible, and headers stay.**
Short documentation still has sections.
It keeps what is needed to understand the code: why it is shaped this way and the known gotchas, never the story of how it got there.

## Writing style

These are hard rules too.
They apply to Markdown, code comments, commit messages, chat replies, error message strings and any prose in scripts.
They are the repository's conventions, applied by default: a report states what the repository does, never presents a convention as the reader's request.

**One thought per line.**
Every sentence starts on its own line, and the renderer joins them back into a paragraph, so a diff shows only the sentence that changed.
A sentence that runs long may continue on the next line at a clause boundary, never mid-clause and never to fit a width.
There is no maximum line length.

**A comment says why, not what, and the why is timeless.**
The code says what it does.
A comment records only what cannot be read off it: the failure it prevents, the constraint that made the obvious shape wrong, the alternative rejected and why.
It is written as if it had always been so: never "used to", never "this replaced", never the story of the session that produced it.
"Filters the parent id with `Eq`, since MongoDB allows one `$text` per query" earns its place, "filter by parent" does not.
A comment that would restate the member name, or a paragraph that walks through the method below it, is left out.

**Never use the em dash (`—`) or the en dash (`–`), nor a spaced hyphen standing in for one.**
Use a colon when introducing an explanation, a comma when joining clauses, or a full stop and a new sentence.

**Never use the second person.**
No "you", no "your", not even in placeholders such as `<your-token>`, which reads `<token>`.
The documentation describes the repository, it does not address a reader.
The contribution terms in `CONTRIBUTING.md` are legal text and the one exception.

**Other conventions.**
Use `ini` as the fence language for `.properties` blocks, never `properties`.
Prefer `>` over `→` for UI navigation, for example **Project Settings > Quality Gate**, arrows remain acceptable in diagrams.

## Repository conventions

This file holds the rules and conventions an agent applies on every change.
The design of each subject, its reasons and its gotchas live in `docs/`, one file per subject, indexed in `docs/README.md`.
A fact is written in one place and linked from elsewhere, never copied, except commands.
What was done and when is git history's, and a sentence that only says something used to be otherwise is deleted rather than kept.

Shell scripts are named in `snake_case` and committed with the executable bit set (`git update-index --chmod=+x path/to/script.sh`), since a script committed as `100644` fails on a fresh clone.

The root `README.md` stays as short as possible.
`CONTRIBUTING.md` holds only the guided steps to be up and running.
Known debt not yet scheduled is listed in `docs/backlog.md`.

Target platform is Linux, including WSL2, and `bash`.

## Commands

```bash
dotnet restore && dotnet build

dotnet run --project src/WebApi      # https://localhost:5011/
dotnet run --project src/BlazorApp   # https://localhost:7042/

dotnet test --project test/WebApi.UnitTests/WebApi.UnitTests.csproj
dotnet test --filter-method "Keeptrack.WebApi.UnitTests.Services.WatchNextServiceTest.ComputeInProgressShows_*"

eval "$(node scripts/load-runsettings.js)"
dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "*WishlistResourceTest*"
```

Integration tests need MongoDB and Firebase test credentials from `Local.runsettings`, loaded by the script above, since `--settings Local.runsettings` runs zero tests.
Those values are never converted into `NAME=value` lines and sourced: [CONTRIBUTING.md](CONTRIBUTING.md#tests) explains both.

## Where to read before changing

File | Read before changing
-----|---------------------
[Architecture](docs/architecture.md) | A controller, error handling, a background job, authorization, the free tier, an admin setting, an outbound HTTP client
[Data model](docs/data-model.md) | A model, entity, DTO, mapper, repository filter, index or stored field name, or when adding a trackable type
[Blazor UI](docs/blazor-ui.md) | A page, a list filter, persisted state, a shared component, styles or icons
[Collections](docs/collections.md) | Ownership, gear, collectibles, playlists, Wishlist, Watch Next, Quick Add, user preferences
[Journals](docs/journals.md) | Car, house or health, their metrics or charts
[Sharing](docs/sharing.md) | The wishlist link or collection sharing
[Imports](docs/imports.md) | A transaction import or the TV Time import
[Explore](docs/explore.md) | The Explore catalogue, its exclusion or paging
[Reference data](docs/reference-data.md) | Enrichment, a reference link, ratings, the sync, the reference export or import
[Reference matching](docs/reference-matching.md) | Anything deciding whether a candidate is a work, before loosening any rule
[Providers](docs/providers.md) | A provider client, its query, quota or registration
[Testing](docs/testing.md) | A test fixture, cleanup, or an end-to-end test
[CI and code quality](docs/ci-and-quality.md) | A workflow, `.istarci.yml`, or a Sonar finding

A new finding is added to the file its subject belongs to, and a reported bug is checked against these files first, since some behavior is by design.

## Quality bar

The owner has zero tolerance for bad design or duplicated algorithms, for new and existing code alike.

- **No duplicated algorithms or logic.**
  Duplicated data *shapes* (Model, Entity and Dto) are expected, duplicated logic over them is not.
  Shared behavior belongs in a base class or shared method, following `DataCrudControllerBase<TDto, TModel>`, `MongoDbRepositoryBase<TModel, TEntity>`, `InventoryPageBase<TDto>`, `ReferenceLinkedDetailPageBase`,
  `JournalDetailPageBase`, `OwnedItemImportCommitCoordinator`, `ChartAxes`.
- **Every non-trivial piece of logic needs a test**, especially per-type overrides like `GetFilter`, where bugs have historically hidden.
- **Don't guess when the information isn't there**: resolution, imports and Watch Next leave something unresolved rather than ship a confident wrong answer.
- **A mocked-repository test cannot prove MongoDB semantics**: filters, collation, null storage and indexes need a real-MongoDB integration test.
- Current best practice for the library and framework version in use is verified before proposing a fix.

## Code style

- Enforced by `.editorconfig`: 4-space indent for C# and Razor, LF endings, `var` everywhere, braces required, `_camelCase` private fields, `s_camelCase` private static, PascalCase otherwise, no `this.`.
- Primary constructors are the norm for controllers, repositories and API clients.
- Nullable reference types are on across `src`, with `required` for non-nullable properties with no sensible default.
- Public `WebApi.Contracts` DTOs and controllers carry XML doc comments, which feed the OpenAPI/Scalar docs.
