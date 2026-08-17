#!/usr/bin/env node
/*
 * Prints the environment variables declared in a `.runsettings` file as shell `export` statements.
 *
 * Why this exists: a filtered CLI test run cannot use the runsettings file.
 * `--filter-method` and `--filter-class` are Microsoft.Testing.Platform flags, and passing `--settings` alongside them switches `dotnet test` to legacy VSTest mode, which rejects them.
 * So a filtered run has to export the same values by hand, and hand-exporting them is where the trap is.
 *
 * The trap: sourcing plain `NAME=value` lines runs every value through shell expansion.
 * A password containing `$` loses everything from the `$` to the next non-word character, silently, and the only symptom is Firebase answering `INVALID_PASSWORD`.
 * A real run lost exactly two characters that way and looked like bad credentials.
 * Every value printed here is therefore single-quoted, with any embedded `'` escaped, and XML entities are decoded first.
 *
 * Usage:
 *   eval "$(node scripts/load-runsettings.js)"
 *   eval "$(node scripts/load-runsettings.js path/to/other.runsettings)"
 *   dotnet test --project test/WebApi.IntegrationTests/WebApi.IntegrationTests.csproj --filter-method "*WishlistResourceTest*"
 *
 * The equivalent PowerShell one-liner is in CONTRIBUTING.md and has no such trap, because `Set-Item -Value` never re-parses what it is given.
 *
 * The file is matched with a regular expression rather than a real parser.
 * That is sound only because a runsettings `EnvironmentVariables` block is a flat list of `<Name>value</Name>` elements with no attributes and no nesting.
 * Anything richer needs a parser, not a longer regular expression.
 */

const fs = require('node:fs');
const path = require('node:path');

const file = process.argv[2] ?? path.join(process.cwd(), 'Local.runsettings');

if (!fs.existsSync(file)) {
    process.stderr.write(`No runsettings file at ${file}\n`);
    process.exit(1);
}

const xml = fs.readFileSync(file, 'utf8');

// Comments are stripped first, so a commented-out variable stays commented out.
// The real file carries one, and a match against the raw text would export it as though it were live.
const block = xml
    .replace(/<!--[\s\S]*?-->/g, '')
    .match(/<EnvironmentVariables>([\s\S]*?)<\/EnvironmentVariables>/);

if (block === null) {
    process.stderr.write(`No <EnvironmentVariables> block in ${file}\n`);
    process.exit(1);
}

// `&amp;` is decoded last, otherwise an escaped entity such as `&amp;lt;` would be decoded twice.
const decode = (value) => value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, '&');

// A single-quoted shell string ends at the first `'`, so an embedded one closes the string, escapes as a literal, and reopens it.
const quote = (value) => `'${value.replace(/'/g, "'\\''")}'`;

const lines = [];
for (const match of block[1].matchAll(/<([A-Za-z_][A-Za-z0-9_]*)>([\s\S]*?)<\/\1>/g)) {
    lines.push(`export ${match[1]}=${quote(decode(match[2]))}`);
}

if (lines.length === 0) {
    process.stderr.write(`No environment variables found in ${file}\n`);
    process.exit(1);
}

process.stderr.write(`Exporting ${lines.length} variables from ${path.basename(file)}\n`);
process.stdout.write(`${lines.join('\n')}\n`);
