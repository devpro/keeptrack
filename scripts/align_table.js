// Reformats a pipe-delimited table (no leading/trailing "|") into a
// column-aligned Markdown table whose delimiter row lines up exactly with
// the header/data pipes, satisfying markdownlint's MD060 (table-column-style).
//
// Usage: node scripts/align_table.js <input.tsv> where columns are separated
// by " | " on the first (header) line, and rows are separated by " | " too.
// Prints the reformatted table to stdout.

function buildTable(rows) {
  const ncols = rows[0].length;
  const widths = new Array(ncols).fill(0);
  for (const row of rows) {
    for (let i = 0; i < ncols; i++) {
      widths[i] = Math.max(widths[i], row[i].length);
    }
  }
  const formatRow = (row) => row.map((cell, i) => cell.padEnd(widths[i])).join(' | ').replace(/\s+$/, '');
  const header = formatRow(rows[0]);
  const separator = header.replace(/[^|]/g, '-');
  const lines = [header, separator, ...rows.slice(1).map(formatRow)];
  return lines.join('\n');
}

const fs = require('fs');
const path = process.argv[2];
if (!path) {
  console.error('Usage: node scripts/align_table.js <input.tsv>');
  process.exit(1);
}
const rows = fs
  .readFileSync(path, 'utf8')
  .split('\n')
  .filter((l) => l.trim().length > 0)
  .map((l) => l.split(' | ').map((c) => c.trim()));
console.log(buildTable(rows));
