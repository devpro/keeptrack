using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class TvTimeImportApiClient(HttpClient http)
{
    public async Task<Guid> StartImportAsync(Stream zipStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(zipStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/tv-time", content);
        response.EnsureSuccessStatusCode();

        var job = await response.Content.ReadFromJsonAsync<ImportJobDto>();
        return job!.JobId;
    }

    public async Task<ImportJobStatusDto> GetStatusAsync(Guid jobId)
    {
        var status = await http.GetFromJsonAsync<ImportJobStatusDto>($"/api/import/tv-time/{jobId}");
        return status ?? new ImportJobStatusDto { Stage = ImportStage.Failed, ErrorMessage = "Lost track of the import job." };
    }
}
