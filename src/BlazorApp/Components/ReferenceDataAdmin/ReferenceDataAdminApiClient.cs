using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.ReferenceDataAdmin;

public sealed class ReferenceDataAdminApiClient(HttpClient http)
{
    public async Task<List<UnresolvedReferenceDto>> GetUnresolvedAsync(ReferenceItemType type)
    {
        var results = await http.GetFromJsonAsync<List<UnresolvedReferenceDto>>($"/api/reference-data/unresolved?type={type}");
        return results ?? [];
    }

    public async Task<List<ReferenceSearchResultDto>> SearchAsync(ReferenceItemType type, string title, int? year, string? creator = null)
    {
        var query = $"/api/reference-data/search?type={type}&title={Uri.EscapeDataString(title)}";
        if (year is not null) query += $"&year={year}";
        if (!string.IsNullOrEmpty(creator)) query += $"&creator={Uri.EscapeDataString(creator)}";

        var results = await http.GetFromJsonAsync<List<ReferenceSearchResultDto>>(query);
        return results ?? [];
    }

    public async Task LinkAsync(LinkReferenceRequestDto request)
    {
        var response = await http.PostAsJsonAsync("/api/reference-data/link", request);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// The full reference dataset (TV shows, movies, cast) as a zip, for seeding a fresh environment.
    /// </summary>
    public async Task<byte[]> ExportAsync()
    {
        var response = await http.GetAsync("/api/reference-data/export");
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync();
    }

    /// <summary>
    /// Idempotent (upsert-by-id) re-import of a previously exported zip.
    /// </summary>
    public async Task<ReferenceDataImportResultDto> ImportAsync(Stream zipStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var streamContent = new StreamContent(zipStream);
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(streamContent, "file", fileName);

        var response = await http.PostAsync("/api/reference-data/import", content);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<ReferenceDataImportResultDto>()
               ?? new ReferenceDataImportResultDto { TvShowCount = 0, MovieCount = 0, PersonCount = 0, BookCount = 0, VideoGameCount = 0, AlbumCount = 0 };
    }

    /// <summary>
    /// Starts an immediate re-check of every reference document against its provider (see
    /// <c>ReferenceDataAdminController.SyncNow</c>), instead of waiting for the periodic background sync.
    /// Runs in the background; poll <see cref="GetSyncStatusAsync"/> with the returned job id for progress.
    /// </summary>
    public async Task<Guid> StartSyncAsync()
    {
        var response = await http.PostAsync("/api/reference-data/sync-now", null);
        response.EnsureSuccessStatusCode();

        var job = await response.Content.ReadFromJsonAsync<ReferenceSyncJobDto>();
        return job!.JobId;
    }

    public async Task<ReferenceSyncJobStatusDto> GetSyncStatusAsync(Guid jobId)
    {
        var status = await http.GetFromJsonAsync<ReferenceSyncJobStatusDto>($"/api/reference-data/sync-now/{jobId}");
        return status ?? new ReferenceSyncJobStatusDto { Stage = ReferenceSyncStage.Failed, ErrorMessage = "Lost track of the sync job." };
    }

    /// <summary>
    /// Operational snapshot: the answering instance's configuration plus the shared reference-sync lease
    /// and recent background jobs (see <c>SystemStatusController</c>).
    /// </summary>
    public async Task<SystemStatusDto?> GetSystemStatusAsync() =>
        await http.GetFromJsonAsync<SystemStatusDto>("/api/system-status");
}
