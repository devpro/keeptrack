using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class AmazonImportApiClient(HttpClient http)
{
    public async Task<List<AmazonOrderPreviewRowDto>> PreviewAsync(Stream csvStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(csvStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/amazon/preview", content);
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<List<AmazonOrderPreviewRowDto>>())!;
    }

    public async Task<AmazonImportCommitResultDto> CommitAsync(List<AmazonImportCommitItemDto> items)
    {
        var response = await http.PostAsJsonAsync("/api/import/amazon/commit", new AmazonImportCommitRequestDto { Items = items });
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<AmazonImportCommitResultDto>())!;
    }
}
