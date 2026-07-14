using System.Net.Http.Headers;
using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.Import;

public sealed class CarHistoryImportApiClient(HttpClient http)
{
    public async Task<CarHistoryImportResultDto> ImportAsync(Stream xlsxStream, string fileName)
    {
        using var content = new MultipartFormDataContent();
        using var fileContent = new StreamContent(xlsxStream);
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        content.Add(fileContent, "file", fileName);

        var response = await http.PostAsync("/api/import/car-history", content);
        response.EnsureSuccessStatusCode();

        return (await response.Content.ReadFromJsonAsync<CarHistoryImportResultDto>())!;
    }
}
