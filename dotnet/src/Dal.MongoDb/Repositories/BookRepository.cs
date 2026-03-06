using AutoMapper;
using KeepTrack.Dal.MongoDb.Entities;
using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.Extensions.Logging;
using MongoDB.Driver;

namespace KeepTrack.Dal.MongoDb.Repositories;

public class BookRepository(IMongoDatabase mongoDatabase, ILogger<RepositoryBase<BookModel, Book>> logger, IMapper mapper)
    : RepositoryBase<BookModel, Book>(mongoDatabase, logger, mapper), IBookRepository
{
    protected override string CollectionName => "book";

    protected override FilterDefinition<Book> GetFilter(string ownerId, string search, BookModel input)
    {
        if (string.IsNullOrEmpty(search))
        {
            return base.GetFilter(ownerId, search, input);
        }

        var builder = Builders<Book>.Filter;
        return builder.Eq(f => f.OwnerId, ownerId) & builder.Where(f => f.Title.ToLower().Contains(search.ToLower())
                                                                        || f.Series.ToLower().Contains(search.ToLower())
                                                                        || f.Author.ToLower().Contains(search.ToLower()));
    }
}
