using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class GenericVideoGameImportApiClient(HttpClient http)
{
    public async Task<List<GenericVideoGameImportPreviewRowDto>> PreviewAsync(Stream csvStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(csvStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/video-games/preview", content);
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<List<GenericVideoGameImportPreviewRowDto>>())!;
    }

    public async Task<GenericVideoGameImportCommitResultDto> CommitAsync(List<GenericVideoGameImportCommitItemDto> items)
    {
        var response = await http.PostAsJsonAsync("/api/import/video-games/commit", new GenericVideoGameImportCommitRequestDto { Items = items });
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<GenericVideoGameImportCommitResultDto>())!;
    }
}
