using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class TvTimeImportApiClient(HttpClient http)
{
    public async Task<ImportResultDto> ImportAsync(Stream zipStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(zipStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/tv-time", content);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<ImportResultDto>();
        return result ?? new ImportResultDto();
    }
}
