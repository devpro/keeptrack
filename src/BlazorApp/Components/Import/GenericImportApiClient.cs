using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class GenericImportApiClient(HttpClient http)
{
    public async Task<List<GenericImportPreviewRowDto>> PreviewAsync(Stream csvStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(csvStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/generic/preview", content);
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<List<GenericImportPreviewRowDto>>())!;
    }

    public async Task<GenericImportCommitResultDto> CommitAsync(List<GenericImportCommitItemDto> items)
    {
        var response = await http.PostAsJsonAsync("/api/import/generic/commit", new GenericImportCommitRequestDto { Items = items });
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<GenericImportCommitResultDto>())!;
    }
}
