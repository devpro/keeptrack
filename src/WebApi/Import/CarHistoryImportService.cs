using System.Globalization;
using ClosedXML.Excel;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using CarEnergyType = Keeptrack.Domain.Models.CarEnergyType;
using CarHistoryType = Keeptrack.Domain.Models.CarHistoryType;

namespace Keeptrack.WebApi.Import;

/// <summary>
/// One-off personal import of the "Voitures.xlsx" spreadsheet:
/// one fuel-log sheet and (optionally) one maintenance-log sheet per car, hand-tracked in French.
/// This is a single-owner spreadsheet with a fixed, known shape (not a generic user-facing file format like the TV Time GDPR export),
/// so the sheet names and column headers below are hardcoded rather than auto-detected. Not idempotent by design -
/// matches an existing car by name so re-running doesn't duplicate the cars themselves, but re-uploading the same file will duplicate history entries.
/// This is meant to be run once per car; unlike <see cref="TvTimeImportService"/>, there is no per-entry natural key in the source data to de-duplicate against.
/// </summary>
public class CarHistoryImportService(ICarRepository carRepository, ICarHistoryRepository carHistoryRepository)
{
    private static readonly CultureInfo French = CultureInfo.GetCultureInfo("fr-FR");

    private sealed record CarSheetGroup(string CarName, string Manufacturer, string Model, string? FuelSheet, string? MaintenanceSheet);

    private static readonly CarSheetGroup[] CarGroups =
    [
        new("First car", "First", "First", "Carburant F", null),
        new("Second car", "Second", "Second", "Carburant S", "Interventions S"),
        new("Third car", "Third", "Third", "Carburant T", "Intervention T")
    ];

    public async Task<CarHistoryImportResultDto> ImportAsync(Stream xlsxStream, string ownerId)
    {
        using var workbook = new XLWorkbook(xlsxStream);
        var result = new CarHistoryImportResultDto();

        var existingCars = (await carRepository.FindAllAsync(ownerId, 1, int.MaxValue, null, NewCar(ownerId, string.Empty))).Items;

        foreach (var group in CarGroups)
        {
            var car = existingCars.FirstOrDefault(c => string.Equals(c.Name, group.CarName, StringComparison.OrdinalIgnoreCase));
            if (car is null)
            {
                car = await carRepository.CreateAsync(new CarModel
                {
                    OwnerId = ownerId,
                    Name = group.CarName,
                    Manufacturer = group.Manufacturer,
                    Model = group.Model,
                    EnergyType = CarEnergyType.Combustion
                });
                result.CarsCreated++;
            }
            else
            {
                result.CarsSkipped++;
            }

            if (group.FuelSheet is not null && workbook.Worksheets.TryGetWorksheet(group.FuelSheet, out var fuelSheet))
            {
                result.HistoryEntriesCreated += await ImportFuelSheetAsync(fuelSheet, car.Id!, ownerId, group.CarName, result.Warnings);
            }

            if (group.MaintenanceSheet is not null && workbook.Worksheets.TryGetWorksheet(group.MaintenanceSheet, out var maintenanceSheet))
            {
                result.HistoryEntriesCreated += await ImportMaintenanceSheetAsync(maintenanceSheet, car.Id!, ownerId, group.CarName, result.Warnings);
            }
        }

        return result;
    }

    private async Task<int> ImportFuelSheetAsync(IXLWorksheet sheet, string carId, string ownerId, string carName, List<string> warnings)
    {
        var headers = ReadHeaders(sheet);
        var created = 0;

        foreach (var row in DataRows(sheet))
        {
            var dateCell = Cell(row, headers, "Date");
            if (dateCell is null || dateCell.IsEmpty()) continue;

            var date = ParseDate(dateCell);
            if (date is null)
            {
                warnings.Add($"{carName}: skipped a fuel entry with an unreadable date (\"{dateCell.GetString()}\").");
                continue;
            }

            var time = ExcelCellParser.ParseTime(Cell(row, headers, "Heure")) ?? TimeOnly.MinValue;

            var entry = new CarHistoryModel
            {
                OwnerId = ownerId,
                CarId = carId,
                HistoryDate = date.Value.ToDateTime(time),
                EventType = CarHistoryType.Refuel,
                City = ExcelCellParser.StringOrNull(Cell(row, headers, "Ville")),
                PostalCode = ExcelCellParser.StringOrNull(Cell(row, headers, "CP")),
                FuelCategory = ExcelCellParser.StringOrNull(Cell(row, headers, "Type carburant")),
                FuelVolume = ExcelCellParser.DoubleOrNull(Cell(row, headers, "Volume (L)")) ?? ExcelCellParser.DoubleOrNull(Cell(row, headers, "Quantité (L)")),
                FuelUnitPrice = ExcelCellParser.PriceOrNull(Cell(row, headers, "Prix (€ / L)")),
                Cost = ExcelCellParser.PriceOrNull(Cell(row, headers, "Prix (€)")) ?? ExcelCellParser.PriceOrNull(Cell(row, headers, "Montant (€)")),
                Mileage = ExcelCellParser.IntOrNull(Cell(row, headers, "Km")),
                DeltaMileage = ExcelCellParser.DoubleOrNull(Cell(row, headers, "Distance (km)")),
                IsFullRefill = IsFlagSet(Cell(row, headers, "Plein")),
                StationBrandName = ExcelCellParser.StringOrNull(Cell(row, headers, "Distributeur")),
                Description = ExcelCellParser.JoinNonEmpty("; ",
                    ExcelCellParser.StringOrNull(Cell(row, headers, "Voyage")) is { } voyage ? $"Voyage : {voyage}" : null,
                    ExcelCellParser.StringOrNull(Cell(row, headers, "Détails")),
                    IsFlagSet(Cell(row, headers, "Autoroute Eloigné")) == true ? "Autoroute/éloigné" : null,
                    IsFlagSet(Cell(row, headers, "Autoroute")) == true ? "Autoroute" : null,
                    IsFlagSet(Cell(row, headers, "Gonflage")) == true ? "Gonflage pneus" : null)
            };

            await carHistoryRepository.CreateAsync(entry);
            created++;
        }

        return created;
    }

    private async Task<int> ImportMaintenanceSheetAsync(IXLWorksheet sheet, string carId, string ownerId, string carName, List<string> warnings)
    {
        var headers = ReadHeaders(sheet);
        var created = 0;

        foreach (var row in DataRows(sheet))
        {
            var dateCell = Cell(row, headers, "Date");
            if (dateCell is null || dateCell.IsEmpty()) continue;

            var date = ParseDate(dateCell);
            if (date is null)
            {
                warnings.Add($"{carName}: skipped a maintenance entry with an unreadable date (\"{dateCell.GetString()}\").");
                continue;
            }

            var nature = ExcelCellParser.StringOrNull(Cell(row, headers, "Nature"));
            var invoiceNumber = ExcelCellParser.StringOrNull(Cell(row, headers, "N° facture"));

            var entry = new CarHistoryModel
            {
                OwnerId = ownerId,
                CarId = carId,
                // Neither maintenance sheet has a time-of-day column, so this always defaults to midnight.
                HistoryDate = date.Value.ToDateTime(TimeOnly.MinValue),
                // "Achat" (purchase) is not a maintenance action - everything else in these two sheets is.
                EventType = string.Equals(nature, "Achat", StringComparison.OrdinalIgnoreCase) ? CarHistoryType.Other : CarHistoryType.Maintenance,
                City = ExcelCellParser.StringOrNull(Cell(row, headers, "Ville")),
                PostalCode = ExcelCellParser.StringOrNull(Cell(row, headers, "CP")),
                Cost = ExcelCellParser.PriceOrNull(Cell(row, headers, "Prix (TTC)")),
                Mileage = ExcelCellParser.IntOrNull(Cell(row, headers, "Km")),
                Garage = ExcelCellParser.StringOrNull(Cell(row, headers, "Garage")),
                Description = ExcelCellParser.JoinNonEmpty("; ",
                    nature,
                    ExcelCellParser.StringOrNull(Cell(row, headers, "Détail")),
                    ExcelCellParser.StringOrNull(Cell(row, headers, "Complément")),
                    invoiceNumber is not null ? $"Facture {invoiceNumber}" : null)
            };

            await carHistoryRepository.CreateAsync(entry);
            created++;
        }

        return created;
    }

    private static CarModel NewCar(string ownerId, string name) => new() { OwnerId = ownerId, Name = name, EnergyType = CarEnergyType.Combustion };

    private static Dictionary<string, int> ReadHeaders(IXLWorksheet sheet)
    {
        var headerRow = sheet.Row(1);
        var headers = new Dictionary<string, int>();
        foreach (var cell in headerRow.CellsUsed())
        {
            // Some headers (e.g. "Autoroute\nEloigné") span two lines within a single cell -
            // normalize whitespace so a lookup doesn't have to guess the exact line-break character used in the file.
            var text = string.Join(' ', cell.GetString().Split([' ', '\r', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries));
            if (text.Length > 0) headers.TryAdd(text, cell.Address.ColumnNumber);
        }

        return headers;
    }

    private static IEnumerable<IXLRow> DataRows(IXLWorksheet sheet) => sheet.RowsUsed().Skip(1);

    private static IXLCell? Cell(IXLRow row, Dictionary<string, int> headers, string header) =>
        headers.TryGetValue(header, out var column) ? row.Cell(column) : null;

    /// <summary>
    /// Reads a date, falling back to a manual French (d/M/yyyy) text parse for the one row that wasn't stored as a real Excel date.
    /// One entry in "Carburant X" has the corrupted literal text "11/06/0207",
    /// confirmed (from the surrounding, chronologically-sorted rows: 2017-08-13 above, 2017-05-26 below) to be a mistyped 11/06/2017 -
    /// fixed here rather than skipped, per a manual review of the source file.
    /// </summary>
    private static DateOnly? ParseDate(IXLCell cell)
    {
        if (cell.TryGetValue(out DateTime dateTime)) return DateOnly.FromDateTime(dateTime);

        var raw = cell.GetString().Trim();
        if (raw == "11/06/0207") return new DateOnly(2017, 6, 11);

        return DateOnly.TryParseExact(raw, "d/M/yyyy", French, DateTimeStyles.None, out var parsed) ? parsed : null;
    }

    private static bool? IsFlagSet(IXLCell? cell)
    {
        if (cell is null || cell.IsEmpty()) return null;
        return string.Equals(cell.GetString().Trim(), "O", StringComparison.OrdinalIgnoreCase);
    }
}
