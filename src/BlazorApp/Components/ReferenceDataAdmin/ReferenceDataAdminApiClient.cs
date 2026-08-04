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

    public async Task<List<ReferenceSearchResultDto>> SearchAsync(ReferenceItemType type, string title, int? year, string? creator = null, string? provider = null, string? isbn = null)
    {
        var query = $"/api/reference-data/search?type={type}&title={Uri.EscapeDataString(title)}";
        if (year is not null) query += $"&year={year}";
        if (!string.IsNullOrEmpty(creator)) query += $"&creator={Uri.EscapeDataString(creator)}";
        if (!string.IsNullOrEmpty(provider)) query += $"&provider={Uri.EscapeDataString(provider)}";
        if (!string.IsNullOrEmpty(isbn)) query += $"&isbn={Uri.EscapeDataString(isbn)}";

        var results = await http.GetFromJsonAsync<List<ReferenceSearchResultDto>>(query);
        return results ?? [];
    }

    /// <summary>
    /// Every registered provider for <paramref name="type"/> (see
    /// <c>ReferenceDataAdminController.GetProviders</c>). Empty for the domains with a single provider, which
    /// is what tells the caller not to render a picker at all.
    /// </summary>
    public async Task<List<ReferenceProviderDto>> GetProvidersAsync(ReferenceItemType type)
    {
        var results = await http.GetFromJsonAsync<List<ReferenceProviderDto>>($"/api/reference-data/providers?type={type}");
        return results ?? [];
    }

    /// <summary>
    /// Every domain whose primary rating source is admin-selectable, with available/selected sources (see
    /// <c>ReferenceDataAdminController.GetRatingSources</c>).
    /// </summary>
    public async Task<List<RatingSourceOptionDto>> GetRatingSourcesAsync()
    {
        var results = await http.GetFromJsonAsync<List<RatingSourceOptionDto>>("/api/reference-data/rating-sources");
        return results ?? [];
    }

    /// <summary>
    /// Stores a domain's primary rating source (does not re-propagate - call <see cref="RecomputeRatingsAsync"/> for that).
    /// </summary>
    public async Task SetRatingSourceAsync(ReferenceItemType domain, string source)
    {
        var response = await http.PutAsJsonAsync($"/api/reference-data/rating-sources/{domain}", new SetRatingSourceRequestDto { Source = source });
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Re-applies a domain's current primary rating source to every linked tenant item (see
    /// <c>ReferenceDataAdminController.RecomputeRatingSource</c>).
    /// </summary>
    public async Task<RecomputeRatingsResultDto> RecomputeRatingsAsync(ReferenceItemType domain)
    {
        var response = await http.PostAsync($"/api/reference-data/rating-sources/{domain}/recompute", null);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<RecomputeRatingsResultDto>() ?? new RecomputeRatingsResultDto();
    }

    /// <summary>The global Explore-feature settings.</summary>
    public async Task<ExploreSettingsDto> GetExploreSettingsAsync() =>
        await http.GetFromJsonAsync<ExploreSettingsDto>("/api/reference-data/explore-settings") ?? new ExploreSettingsDto();

    /// <summary>Updates the global Explore-feature settings.</summary>
    public async Task SetExploreSettingsAsync(bool useTmdbRanking)
    {
        var response = await http.PutAsJsonAsync("/api/reference-data/explore-settings", new ExploreSettingsDto { UseTmdbRanking = useTmdbRanking });
        response.EnsureSuccessStatusCode();
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
    /// Re-import of a previously exported zip. Documents are matched by provider id, not by the <c>_id</c>
    /// they were exported with, so this is idempotent and safe against a database that already holds some of
    /// the same references - see <c>ReferenceDataImportService</c>.
    /// <para>
    /// Runs in the background; poll <see cref="GetImportStatusAsync"/> with the returned job id for progress.
    /// A real export is tens of thousands of documents, which takes far longer than this client's default
    /// 100s timeout - waiting on one response reported a timeout for an import that was still running fine.
    /// </para>
    /// </summary>
    /// <param name="zipStream">
    /// Read to the end before the request is sent, so pass a stream that is already in memory. Handing
    /// <c>IBrowserFile.OpenReadStream()</c> straight to <see cref="StreamContent"/> makes the API wait on the
    /// browser drip-feeding the file down the SignalR circuit mid-request.
    /// </param>
    public async Task<Guid> StartImportAsync(Stream zipStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var streamContent = new StreamContent(zipStream);
        streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(streamContent, "file", fileName);

        var response = await http.PostAsync("/api/reference-data/import", content);
        response.EnsureSuccessStatusCode();

        var job = await response.Content.ReadFromJsonAsync<ReferenceDataImportJobDto>();
        return job!.JobId;
    }

    public async Task<ReferenceDataImportJobStatusDto> GetImportStatusAsync(Guid jobId)
    {
        var status = await http.GetFromJsonAsync<ReferenceDataImportJobStatusDto>($"/api/reference-data/import/{jobId}");
        return status ?? new ReferenceDataImportJobStatusDto { Stage = ReferenceDataImportStage.Failed, ErrorMessage = "Lost track of the import job." };
    }

    /// <summary>
    /// Runs the reference sync now instead of waiting for the periodic background one (see
    /// <c>ReferenceDataAdminController.SyncNow</c>). With <paramref name="force"/> it re-checks every
    /// reference document and rebuilds every Explore ranking; without it, it takes exactly what the
    /// background tick would have taken - only what is past its staleness window.
    /// Runs in the background; poll <see cref="GetSyncStatusAsync"/> with the returned job id for progress.
    /// </summary>
    public async Task<Guid> StartSyncAsync(bool force)
    {
        var response = await http.PostAsync($"/api/reference-data/sync-now?force={force}", null);
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
