using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AutoMapper;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Bson;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class BookRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<BookModel, Book>> logger, IMapper mapper)
    : MongoDbRepositoryBase<BookModel, Book>(mongoDatabase, logger, mapper), IBookRepository
{
    protected override string CollectionName => "book";

    protected override FilterDefinition<Book> GetFilter(string ownerId, string? search, BookModel input)
    {
        var builder = Builders<Book>.Filter;
        var filter = builder.Eq(f => f.OwnerId, ownerId);
        if (!string.IsNullOrEmpty(search)) filter &= builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                                                         || (f.Series != null && f.Series.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                                                         || f.Author.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
        if (input.IsFavorite) filter &= builder.Eq(f => f.IsFavorite, true);
        return filter;
    }

    public async Task<long> SetReferenceLinkAsync(string title, int? year, string referenceId, string canonicalTitle, int? canonicalYear = null, string? canonicalAuthor = null, string? canonicalGenre = null)
    {
        var builder = Builders<Book>.Filter;
        var filter = builder.Regex(f => f.Title, new BsonRegularExpression($"^{Regex.Escape(title)}$", "i"))
                     & builder.Eq(f => f.Year, year)
                     & UnresolvedFilter();

        var update = Builders<Book>.Update.Set(f => f.ReferenceId, referenceId).Set(f => f.Title, canonicalTitle);
        if (canonicalYear is not null) update = update.Set(f => f.Year, canonicalYear);
        if (canonicalAuthor is not null) update = update.Set(f => f.Author, canonicalAuthor);
        if (canonicalGenre is not null) update = update.Set(f => f.Genre, canonicalGenre);
        var result = await GetCollection().UpdateManyAsync(filter, update);
        return result.ModifiedCount;
    }

    public async Task<IReadOnlyList<(string Title, int? Year)>> FindDistinctUnresolvedTitleYearsAsync()
    {
        var groups = await GetCollection().Aggregate()
            .Match(UnresolvedFilter())
            .Group(f => new { f.Title, f.Year }, g => g.Key)
            .ToListAsync();
        return groups.Select(g => (g.Title, g.Year)).ToList();
    }

    /// <summary>
    /// "Has no reference link yet" means <see cref="Book.ReferenceId"/> is null OR empty string, not
    /// just null: AutoMapper is configured with <c>AllowNullDestinationValues = false</c> (see Program.cs),
    /// so mapping a model with a null string property stores an empty string, never an actual null.
    /// </summary>
    private static FilterDefinition<Book> UnresolvedFilter()
    {
        var builder = Builders<Book>.Filter;
        return builder.Eq(f => f.ReferenceId, null) | builder.Eq(f => f.ReferenceId, string.Empty);
    }
}
