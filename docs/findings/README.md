# Code quality findings

The why behind the code and its known gotchas, in more detail than `AGENTS.md`.
Read the relevant file when a question comes up, and check it before reporting something as a bug or changing a rule.
A new finding goes in the file its subject belongs to.

- [Reference matching](reference-matching.md): aliases, what confirms a match, and why a link survives an edit.
- [Video game matching](video-game-matching.md): the hardest domain, with same-titled works, remakes and DLC.
- [Third-party providers](providers.md): outages, quotas, query quirks, and how a provider failure is reported.
- [Sync, Explore and import](sync-explore-and-import.md): the work that runs on a schedule or in the background.
- [Blazor UI](blazor-ui.md): rendering after navigation, the pending-link watch, and 404s.
- [Persistence and mapping](persistence-and-mapping.md): MongoDB filters, indexes and null handling.
- [Sonar](sonar.md): standing false positives, and fixes worth explaining.
- [By design, and known gaps](by-design-and-gaps.md): what not to "fix", and what is not done yet.
