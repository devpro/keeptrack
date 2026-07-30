using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Keeptrack.WebApi.ReferenceData;

namespace Keeptrack.WebApi.UnitTests.ReferenceData;

/// <summary>
/// Test double for OMDb (IMDb ratings): returns a rating for any imdb id seeded in <see cref="Ratings"/>,
/// null otherwise (the "no OMDb key / no rating" case), and records which ids were queried so a test can
/// assert the cheap backfill did or didn't call the provider.
/// </summary>
internal sealed class FakeOmdbClient : IOmdbClient
{
    public Dictionary<string, OmdbRating> Ratings { get; } = new();

    public List<string> Requested { get; } = [];

    public static FakeOmdbClient Empty() => new();

    public Task<OmdbRating?> GetRatingAsync(string imdbId, CancellationToken cancellationToken = default)
    {
        Requested.Add(imdbId);
        return Task.FromResult(Ratings.GetValueOrDefault(imdbId));
    }
}
