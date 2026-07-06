using Keeptrack.WebApi.Contracts.Dto;

namespace Keeptrack.BlazorApp.Components.ReferenceDataAdmin;

public sealed class ReferenceDataAdminApiClient(HttpClient http)
{
    public async Task<List<UnresolvedReferenceDto>> GetUnresolvedAsync(ReferenceItemType type)
    {
        var results = await http.GetFromJsonAsync<List<UnresolvedReferenceDto>>($"/api/reference-data/unresolved?type={type}");
        return results ?? [];
    }

    public async Task<List<ReferenceSearchResultDto>> SearchAsync(ReferenceItemType type, string title, int? year)
    {
        var query = $"/api/reference-data/search?type={type}&title={Uri.EscapeDataString(title)}";
        if (year is not null) query += $"&year={year}";

        var results = await http.GetFromJsonAsync<List<ReferenceSearchResultDto>>(query);
        return results ?? [];
    }

    public async Task LinkAsync(LinkReferenceRequestDto request)
    {
        var response = await http.PostAsJsonAsync("/api/reference-data/link", request);
        response.EnsureSuccessStatusCode();
    }
}
