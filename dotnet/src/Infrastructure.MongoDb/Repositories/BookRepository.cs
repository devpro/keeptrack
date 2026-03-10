using AutoMapper;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using KeepTrack.Infrastructure.MongoDb.Entities;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Infrastructure.MongoDb.Repositories;

public class BookRepository(IMongoDatabase mongoDatabase, ILogger<MongoDbRepositoryBase<BookModel, Book>> logger, IMapper mapper)
    : MongoDbRepositoryBase<BookModel, Book>(mongoDatabase, logger, mapper), IBookRepository
{
    protected override string CollectionName => "book";

    protected override FilterDefinition<Book> GetFilter(string ownerId, string? search, BookModel input)
    {
        var builder = Builders<Book>.Filter;
        if (string.IsNullOrEmpty(search)) return builder.Eq(f => f.OwnerId, ownerId);
        return builder.Eq(f => f.OwnerId, ownerId)
               & builder.Where(f => f.Title.Contains(search, System.StringComparison.CurrentCultureIgnoreCase)
                                    || (f.Series == null || f.Series.Contains(search, System.StringComparison.CurrentCultureIgnoreCase))
                                    || f.Author.Contains(search, System.StringComparison.CurrentCultureIgnoreCase));
    }
}
