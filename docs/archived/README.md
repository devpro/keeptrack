# Archived documents

Finished work kept for provenance only.
Nothing here describes how the application currently behaves: `AGENTS.md` is the authority for that, and `docs/findings/` tracks open findings.
A document lands here once its plan has shipped, its migration has run, or its snapshot has been overtaken by the code.

Document                         | What it was                                                                      | Why it is archived
---------------------------------|----------------------------------------------------------------------------------|-------------------
`automapper-removal-plan.md`     | Plan to replace AutoMapper with Riok.Mapperly, and the licensing reason for it.   | The migration shipped, Mapperly is the only mapper left.
`plan-quick-add.md`              | Design for the one-tap Quick Add capture form.                                    | Shipped as `BlazorApp/Components/QuickAdd`.
`playwright-e2e-tests-plan.md`   | Original design of the Playwright e2e suite and its environment variables.        | The suite exists, `CONTRIBUTING.md` documents the current `E2E_*` surface.
`prerender-flash-fix.md`         | Investigation of the .NET 10 prerender double-render flash.                       | Fixed, the remaining code comments point back here for the reasoning.
`reference-ratings-plan.md`      | Design of provider reference ratings, written when RAWG was the game provider.    | Shipped, and the video game half was superseded by IGDB.
`share-collections-plan.md`      | Design for sharing whole categories with other Keeptrack accounts.                | Shipped as `ShareController`/`SharedWithMeController`.
`testing-assessment.md`          | Snapshot of the test suite as of 2026-07-27.                                      | A dated inventory, overtaken by the suite itself.
