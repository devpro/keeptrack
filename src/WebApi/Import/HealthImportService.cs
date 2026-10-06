using ClosedXML.Excel;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using HealthEventType = Keeptrack.Domain.Models.HealthEventType;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// One-off personal import of the "Journal_sante.xlsx" spreadsheet: one sheet of health events kept by hand in French, every family member in one "Personne" column.
/// Rows go to one <see cref="HealthProfileModel"/> per person, created when needed.
/// Not idempotent, like <see cref="CarHistoryImportService"/>: profiles are matched by name, but uploading the file again duplicates the entries.
/// The "Reste à charge" column is not imported: it is a formula (paid minus ameli and mutuelle),
/// and importing it as <see cref="HealthRecordModel.NotCovered"/> would mark every past row settled.
/// The rows the balance check flags are those the owner wants to verify.
/// </summary>
public class HealthImportService(IHealthProfileRepository healthProfileRepository, IHealthRecordRepository healthRecordRepository)
{
    /// <summary>
    /// Column positions resolved from the header row.
    /// Two columns are titled "Personne", the patient then the practitioner, so a header-to-column dictionary like the car import's cannot represent the sheet.
    /// "Jour" and "Reste à charge", both derived, are ignored.
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
            await ImportRowAsync(row, columns, ownerId, profilesByName, result);
        }

        result.ProfilesSkipped = profilesByName.Count - result.ProfilesCreated;
        return result;
    }

    private async Task ImportRowAsync(IXLRow row, SheetColumns columns, string ownerId,
        Dictionary<string, HealthProfileModel> profilesByName, HealthImportResultDto result)
    {
        var dateCell = row.Cell(columns.Date!.Value);
        if (dateCell.IsEmpty()) return;
        if (!dateCell.TryGetValue(out DateTime date))
        {
            result.Warnings.Add($"Row {row.RowNumber()}: skipped, unreadable date (\"{dateCell.GetString()}\").");
            return;
        }

        var personName = ExcelCellParser.StringOrNull(Cell(row, columns.Person));
        if (personName is null)
        {
            result.Warnings.Add($"Row {row.RowNumber()}: skipped, no \"Personne\" to attach the entry to.");
            return;
        }

        var target = await GetOrCreateProfileAsync(personName, ownerId, profilesByName, result);
        await healthRecordRepository.CreateAsync(BuildRecord(row, columns, ownerId, target, date));
        result.RecordsCreated++;
    }

    private async Task<HealthProfileModel> GetOrCreateProfileAsync(string personName, string ownerId,
        Dictionary<string, HealthProfileModel> profilesByName, HealthImportResultDto result)
    {
        if (profilesByName.TryGetValue(personName, out var target)) return target;

        target = await healthProfileRepository.CreateAsync(new HealthProfileModel { OwnerId = ownerId, Name = personName });
        profilesByName[personName] = target;
        result.ProfilesCreated++;
        return target;
    }

    private static HealthRecordModel BuildRecord(IXLRow row, SheetColumns columns, string ownerId, HealthProfileModel target, DateTime date)
    {
        var time = ExcelCellParser.ParseTime(Cell(row, columns.Time)) ?? TimeOnly.MinValue;

        return new HealthRecordModel
        {
            OwnerId = ownerId,
            HealthProfileId = target.Id!,
            HistoryDate = DateOnly.FromDateTime(date).ToDateTime(time),
            // every row of this journal is a care event, sicknesses not being tracked in it
            EventType = HealthEventType.Appointment,
            Specialty = ExcelCellParser.StringOrNull(Cell(row, columns.Specialty)),
            Practitioner = ExcelCellParser.StringOrNull(Cell(row, columns.Practitioner)),
            Description = ExcelCellParser.StringOrNull(Cell(row, columns.Description)),
            Price = ExcelCellParser.PriceOrNull(Cell(row, columns.Paid)),
            PublicReimbursement = ExcelCellParser.PriceOrNull(Cell(row, columns.PublicReimbursement)),
            InsuranceReimbursement = ExcelCellParser.PriceOrNull(Cell(row, columns.InsuranceReimbursement)),
            // the sparse bookkeeping columns (place, ameli transfer, payment dates, comment) have no fields, so they are kept as labeled notes
            Notes = ExcelCellParser.JoinNonEmpty("; ",
                ExcelCellParser.StringOrNull(Cell(row, columns.Notes)),
                ExcelCellParser.StringOrNull(Cell(row, columns.Location)) is { } location ? $"Lieu : {location}" : null,
                ExcelCellParser.PriceOrNull(Cell(row, columns.PublicTransfer)) is { } transfer ? $"Virement Ameli : {transfer:F2}" : null,
                DateTextOrNull(Cell(row, columns.PublicDate)) is { } publicDate ? $"Payé Ameli le {publicDate}" : null,
                DateTextOrNull(Cell(row, columns.InsuranceDate)) is { } insuranceDate ? $"Payé mutuelle le {insuranceDate}" : null,
                ExcelCellParser.StringOrNull(Cell(row, columns.Comment)))
        };
    }

    private static SheetColumns ReadColumns(IXLWorksheet sheet)
    {
        var columns = new SheetColumns();
        foreach (var cell in sheet.Row(1).CellsUsed())
        {
            // headers like "Rbrst\nAmeli" span two lines in a cell, so whitespace is normalized
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
