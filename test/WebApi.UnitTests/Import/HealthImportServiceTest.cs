using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AwesomeAssertions;
using ClosedXML.Excel;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.WebApi.Import;
using Xunit;

namespace Keeptrack.WebApi.UnitTests.Import;

/// <summary>
/// Exercises <see cref="HealthImportService"/> against an in-memory workbook shaped exactly like the
/// real "Journal_sante.xlsx" (verified against the actual file): the duplicate "Personne" header (first =
/// who was treated, second = practitioner), two-line headers like "Rbrst\nAmeli", Excel-native dates and
/// time fractions, formula-backed amounts, and the derived "Reste à charge" column that must NOT be
/// imported.
/// </summary>
[Trait("Category", "UnitTests")]
public class HealthImportServiceTest
{
    private readonly FakeHealthProfileRepository _profiles = new();
    private readonly FakeHealthRecordRepository _records = new();

    private HealthImportService CreateService() => new(_profiles, _records);

    private static byte[] BuildWorkbook(Action<IXLWorksheet>? mutate = null)
    {
        using var workbook = new XLWorkbook();
        var sheet = workbook.AddWorksheet("Journal");

        string[] headers = ["Jour", "Date", "Heure", "Personne", "Spécialité", "Personne", "Lieu", "Fait", "Notes", "Paiement", "Rbrst\nAmeli", "Virt Ameli", "Date Ameli", "Rbrst\nMutuelle", "Date\nmutuelle", "Reste\nà charge", "Commentaire"];
        for (var i = 0; i < headers.Length; i++) sheet.Cell(1, i + 1).Value = headers[i];

        // a settled consultation for Bertrand, with a time of day
        sheet.Cell(2, 1).Value = "Lundi";
        sheet.Cell(2, 2).Value = new DateTime(2022, 9, 21);
        sheet.Cell(2, 3).Value = new TimeSpan(10, 0, 0);
        sheet.Cell(2, 4).Value = "Bertrand";
        sheet.Cell(2, 5).Value = "Ostéopathe";
        sheet.Cell(2, 6).Value = "Dr Roche";
        sheet.Cell(2, 8).Value = "Consultation";
        sheet.Cell(2, 10).Value = 60;
        sheet.Cell(2, 11).Value = 0;
        sheet.Cell(2, 14).Value = 60;
        sheet.Cell(2, 16).FormulaA1 = "=J2-K2-N2"; // the derived column the import must ignore

        // a partially reimbursed one for a second person, with the bookkeeping extras
        sheet.Cell(3, 2).Value = new DateTime(2022, 9, 27);
        sheet.Cell(3, 4).Value = "Vinciane";
        sheet.Cell(3, 5).Value = "Médecin généraliste";
        sheet.Cell(3, 8).Value = "Consultation";
        sheet.Cell(3, 10).Value = 25;
        sheet.Cell(3, 14).Value = 7.5;
        sheet.Cell(3, 17).Value = "Envoyé le 22/12 à NoveoCare";

        // a formula-backed amount with floating-point noise, same person as row 2
        sheet.Cell(4, 2).Value = new DateTime(2022, 12, 18);
        sheet.Cell(4, 4).Value = "Bertrand";
        sheet.Cell(4, 10).FormulaA1 = "=17.5+18.55";

        // an unreadable date and a missing person - both skipped with a warning, never guessed at
        sheet.Cell(5, 2).Value = "pas une date";
        sheet.Cell(5, 4).Value = "Bertrand";
        sheet.Cell(6, 2).Value = new DateTime(2023, 1, 5);

        mutate?.Invoke(sheet);

        using var stream = new MemoryStream();
        workbook.SaveAs(stream);
        return stream.ToArray();
    }

    [Fact]
    public async Task Import_CreatesOneProfilePerDistinctPerson_AndAttachesTheirRecords()
    {
        var result = await CreateService().ImportAsync(new MemoryStream(BuildWorkbook()), "owner-1");

        result.ProfilesCreated.Should().Be(2);
        result.ProfilesSkipped.Should().Be(0);
        result.RecordsCreated.Should().Be(3);
        result.Warnings.Should().HaveCount(2);

        var bertrand = _profiles.Items.Single(p => p.Name == "Bertrand");
        _records.Items.Count(r => r.HealthProfileId == bertrand.Id).Should().Be(2);
    }

    [Fact]
    public async Task Import_MapsEveryColumn_IncludingTheSecondPersonneAsPractitioner_AndKeepsTheTime()
    {
        await CreateService().ImportAsync(new MemoryStream(BuildWorkbook()), "owner-1");

        var consultation = _records.Items.Single(r => r.Specialty == "Ostéopathe");
        consultation.HistoryDate.Should().Be(new DateTime(2022, 9, 21, 10, 0, 0));
        consultation.EventType.Should().Be(HealthEventType.Appointment);
        consultation.Practitioner.Should().Be("Dr Roche");
        consultation.Description.Should().Be("Consultation");
        consultation.Price.Should().Be(60);
        consultation.PublicReimbursement.Should().Be(0);
        consultation.InsuranceReimbursement.Should().Be(60);
        // the derived "Reste à charge" column is never imported - the app recomputes the balance
        consultation.NotCovered.Should().BeNull();
    }

    [Fact]
    public async Task Import_PreservesBookkeepingColumnsAsNotes_AndRoundsFormulaAmounts()
    {
        await CreateService().ImportAsync(new MemoryStream(BuildWorkbook()), "owner-1");

        var vinciane = _records.Items.Single(r => r.Specialty == "Médecin généraliste");
        vinciane.Notes.Should().Be("Envoyé le 22/12 à NoveoCare");

        var formulaRow = _records.Items.Single(r => r.HistoryDate.Date == new DateTime(2022, 12, 18));
        formulaRow.Price.Should().Be(36.05);
    }

    [Fact]
    public async Task Import_MatchesExistingProfilesByName_InsteadOfDuplicatingThem()
    {
        await _profiles.CreateAsync(new HealthProfileModel { OwnerId = "owner-1", Name = "bertrand" }); // case differs on purpose

        var result = await CreateService().ImportAsync(new MemoryStream(BuildWorkbook()), "owner-1");

        result.ProfilesCreated.Should().Be(1); // only Vinciane
        result.ProfilesSkipped.Should().Be(1);
        _profiles.Items.Should().HaveCount(2);
    }

    private class InMemoryRepository<TModel>
        where TModel : class, IHasIdAndOwnerId
    {
        public List<TModel> Items { get; } = [];

        public Task<TModel?> FindOneAsync(string id, string ownerId) =>
            Task.FromResult(Items.FirstOrDefault(x => x.Id == id && x.OwnerId == ownerId));

        public Task<long> CountAsync(string ownerId) =>
            Task.FromResult((long)Items.Count(x => x.OwnerId == ownerId));

        public Task<PagedResult<TModel>> FindAllAsync(string ownerId, int page, int pageSize, string? search, TModel input, string? sort = null)
        {
            var items = Items.Where(x => x.OwnerId == ownerId).ToList();
            return Task.FromResult(new PagedResult<TModel>(items, items.Count, page, pageSize));
        }

        public Task<TModel> CreateAsync(TModel model)
        {
            model.Id ??= Guid.NewGuid().ToString();
            Items.Add(model);
            return Task.FromResult(model);
        }

        public Task<long> UpdateAsync(string id, TModel model, string ownerId) => Task.FromResult(1L);

        public Task<long> DeleteAsync(string id, string ownerId) =>
            Task.FromResult((long)Items.RemoveAll(x => x.Id == id && x.OwnerId == ownerId));
    }

    private sealed class FakeHealthProfileRepository : InMemoryRepository<HealthProfileModel>, IHealthProfileRepository;

    private sealed class FakeHealthRecordRepository : InMemoryRepository<HealthRecordModel>, IHealthRecordRepository
    {
        public Task<long> DeleteAllForProfileAsync(string healthProfileId, string ownerId) =>
            Task.FromResult((long)Items.RemoveAll(x => x.HealthProfileId == healthProfileId && x.OwnerId == ownerId));
    }
}
