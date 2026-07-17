using ClosedXML.Excel;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using HealthEventType = Keeptrack.Domain.Models.HealthEventType;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// One-off personal import of the "Journal_sante.xlsx" spreadsheet: a single sheet of hand-tracked
/// health events in French, mixing every family member in one "Personne" column - so unlike the car
/// import, rows are dispatched to (and, when needed, create) one <see cref="HealthProfileModel"/> per
/// distinct person. Same non-idempotence trade-off as <see cref="CarHistoryImportService"/>: profiles
/// are matched by name so re-running doesn't duplicate the people, but re-uploading the same file will
/// duplicate journal entries - there is no per-row natural key to de-duplicate against.
/// The "Reste à charge" column is deliberately NOT imported: it's a formula in the source file
/// (paid - ameli - mutuelle), i.e. derived data the app recomputes itself (see
/// <see cref="Domain.Services.HealthMetricsService"/>) - importing its cached value as
/// <see cref="HealthRecordModel.NotCovered"/> would silently mark every historical row as settled.
/// Rows the balance check then flags are exactly the ones the owner wants to re-verify.
/// </summary>
public class HealthImportService(IHealthProfileRepository healthProfileRepository, IHealthRecordRepository healthRecordRepository)
{
    /// <summary>
    /// Column positions resolved from the header row. The file has TWO columns titled "Personne" - the
    /// first is who was treated (the profile), the second the practitioner - so a plain
    /// header-name-to-column dictionary (the car importer's approach) can't represent this sheet.
    /// "Jour" (derived day-of-week) and "Reste à charge" (derived, see the class remarks) are ignored.
    /// </summary>
    private sealed class SheetColumns
    {
        public int? Date { get; set; }
        public int? Time { get; set; }
        public int? Person { get; set; }
        public int? Practitioner { get; set; }
        public int? Specialty { get; set; }
        public int? Location { get; set; }
        public int? Description { get; set; }
        public int? Notes { get; set; }
        public int? Paid { get; set; }
        public int? PublicReimbursement { get; set; }
        public int? PublicTransfer { get; set; }
        public int? PublicDate { get; set; }
        public int? InsuranceReimbursement { get; set; }
        public int? InsuranceDate { get; set; }
        public int? Comment { get; set; }
    }

    public async Task<HealthImportResultDto> ImportAsync(Stream xlsxStream, string ownerId)
    {
        using var workbook = new XLWorkbook(xlsxStream);
        var sheet = workbook.Worksheets.First();
        var columns = ReadColumns(sheet);
        var result = new HealthImportResultDto();

        if (columns.Date is null || columns.Person is null)
        {
            result.Warnings.Add("The sheet has no \"Date\"/\"Personne\" header row - nothing was imported.");
            return result;
        }

        var profilesByName = new Dictionary<string, HealthProfileModel>(StringComparer.OrdinalIgnoreCase);
        var existingProfiles = (await healthProfileRepository.FindAllAsync(ownerId, 1, int.MaxValue, null,
            new HealthProfileModel { OwnerId = ownerId, Name = string.Empty })).Items;
        foreach (var profile in existingProfiles) profilesByName.TryAdd(profile.Name.Trim(), profile);

        foreach (var row in sheet.RowsUsed().Skip(1))
        {
            var dateCell = row.Cell(columns.Date.Value);
            if (dateCell.IsEmpty()) continue;
            if (!dateCell.TryGetValue(out DateTime date))
            {
                result.Warnings.Add($"Row {row.RowNumber()}: skipped, unreadable date (\"{dateCell.GetString()}\").");
                continue;
            }

            var personName = ExcelCellParser.StringOrNull(Cell(row, columns.Person));
            if (personName is null)
            {
                result.Warnings.Add($"Row {row.RowNumber()}: skipped, no \"Personne\" to attach the entry to.");
                continue;
            }

            if (!profilesByName.TryGetValue(personName, out var target))
            {
                target = await healthProfileRepository.CreateAsync(new HealthProfileModel { OwnerId = ownerId, Name = personName });
                profilesByName[personName] = target;
                result.ProfilesCreated++;
            }

            var time = ExcelCellParser.ParseTime(Cell(row, columns.Time)) ?? TimeOnly.MinValue;

            await healthRecordRepository.CreateAsync(new HealthRecordModel
            {
                OwnerId = ownerId,
                HealthProfileId = target.Id!,
                HistoryDate = DateOnly.FromDateTime(date).ToDateTime(time),
                // every row in this journal is a care event; sicknesses weren't tracked in the spreadsheet
                EventType = HealthEventType.Appointment,
                Specialty = ExcelCellParser.StringOrNull(Cell(row, columns.Specialty)),
                Practitioner = ExcelCellParser.StringOrNull(Cell(row, columns.Practitioner)),
                Description = ExcelCellParser.StringOrNull(Cell(row, columns.Description)),
                Price = ExcelCellParser.PriceOrNull(Cell(row, columns.Paid)),
                PublicReimbursement = ExcelCellParser.PriceOrNull(Cell(row, columns.PublicReimbursement)),
                InsuranceReimbursement = ExcelCellParser.PriceOrNull(Cell(row, columns.InsuranceReimbursement)),
                // the sparse bookkeeping columns (place, actual ameli bank transfer, payment dates,
                // comment) have no dedicated fields - preserved as labeled notes instead of dropped
                Notes = ExcelCellParser.JoinNonEmpty("; ",
                    ExcelCellParser.StringOrNull(Cell(row, columns.Notes)),
                    ExcelCellParser.StringOrNull(Cell(row, columns.Location)) is { } location ? $"Lieu : {location}" : null,
                    ExcelCellParser.PriceOrNull(Cell(row, columns.PublicTransfer)) is { } transfer ? $"Virement Ameli : {transfer:F2}" : null,
                    DateTextOrNull(Cell(row, columns.PublicDate)) is { } publicDate ? $"Payé Ameli le {publicDate}" : null,
                    DateTextOrNull(Cell(row, columns.InsuranceDate)) is { } insuranceDate ? $"Payé mutuelle le {insuranceDate}" : null,
                    ExcelCellParser.StringOrNull(Cell(row, columns.Comment)))
            });
            result.RecordsCreated++;
        }

        result.ProfilesSkipped = profilesByName.Count - result.ProfilesCreated;
        return result;
    }

    private static SheetColumns ReadColumns(IXLWorksheet sheet)
    {
        var columns = new SheetColumns();
        foreach (var cell in sheet.Row(1).CellsUsed())
        {
            // headers like "Rbrst\nAmeli" span two lines within one cell; normalize the whitespace
            var text = string.Join(' ', cell.GetString().Split([' ', '\r', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries));
            var column = cell.Address.ColumnNumber;
            switch (text)
            {
                case "Date": columns.Date ??= column; break;
                case "Heure": columns.Time ??= column; break;
                case "Personne" when columns.Person is null: columns.Person = column; break;
                case "Personne": columns.Practitioner ??= column; break;
                case "Spécialité": columns.Specialty ??= column; break;
                case "Lieu": columns.Location ??= column; break;
                case "Fait": columns.Description ??= column; break;
                case "Notes": columns.Notes ??= column; break;
                case "Paiement": columns.Paid ??= column; break;
                case "Rbrst Ameli": columns.PublicReimbursement ??= column; break;
                case "Virt Ameli": columns.PublicTransfer ??= column; break;
                case "Date Ameli": columns.PublicDate ??= column; break;
                case "Rbrst Mutuelle": columns.InsuranceReimbursement ??= column; break;
                case "Date mutuelle": columns.InsuranceDate ??= column; break;
                case "Commentaire": columns.Comment ??= column; break;
            }
        }

        return columns;
    }

    private static IXLCell? Cell(IXLRow row, int? column) => column is null ? null : row.Cell(column.Value);

    private static string? DateTextOrNull(IXLCell? cell)
    {
        if (cell is null || cell.IsEmpty()) return null;
        return cell.TryGetValue(out DateTime date) ? date.ToString("yyyy-MM-dd") : ExcelCellParser.StringOrNull(cell);
    }
}
