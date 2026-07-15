using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Infrastructure.MongoDb.Entities;
using Keeptrack.Infrastructure.MongoDb.Mappers;
using MongoDB.Driver;

namespace Keeptrack.Infrastructure.MongoDb.Repositories;

public class BookReferenceRepository(IMongoDatabase mongoDatabase, BookReferenceStorageMapper mapper) : IBookReferenceRepository
{
    private const string CollectionName = "book_reference";

    private IMongoCollection<BookReference> Collection => mongoDatabase.GetCollection<BookReference>(CollectionName);

    public async Task<BookReferenceModel?> FindByIdAsync(string id)
    {
        var entity = await Collection.Find(x => x.Id == id).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<BookReferenceModel>> FindByIdsAsync(IReadOnlyCollection<string> ids)
    {
        if (ids.Count == 0) return [];
        var entities = await Collection.Find(Builders<BookReference>.Filter.In(x => x.Id, ids)).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var normalizedAuthor = TitleNormalizer.Normalize(author);
        var filter = Builders<BookReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Year, year)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, normalizedAuthor));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<BookReferenceModel?> FindByTitleAsync(string title, string author)
    {
        var normalized = TitleNormalizer.Normalize(title);
        var normalizedAuthor = TitleNormalizer.Normalize(author);
        var filter = Builders<BookReference>.Filter.ElemMatch(x => x.MatchedAliases,
            Builders<ReferenceMatch>.Filter.Eq(m => m.Title, normalized)
            & Builders<ReferenceMatch>.Filter.Eq(m => m.Creator, normalizedAuthor));
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<BookReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<BookReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<BookReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<BookReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<BookReferenceModel> UpsertAsync(BookReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // this safety net can't know the canonical author text (the model only carries AuthorReferenceId,
        // a dedup'd link, not denormalized text), so an alias added here has no Creator and simply won't
        // match via FindByTitleYearAsync/FindByTitleAsync's required-creator filter - harmless, since the
        // normal Resolve/Refresh path always adds a proper creator-bearing alias via MergeMatchedAliases
        // before calling UpsertAsync; this only guards a caller that skipped that step entirely.
        if (!model.MatchedAliases.Any(m => m.Title == model.TitleNormalized && m.Year == model.Year))
        {
            model.MatchedAliases.Add(new ReferenceMatchModel { Title = model.TitleNormalized, Year = model.Year });
        }
        var entity = mapper.ToEntity(model);

        if (string.IsNullOrEmpty(entity.Id))
        {
            await Collection.InsertOneAsync(entity);
        }
        else
        {
            await Collection.ReplaceOneAsync(x => x.Id == entity.Id, entity, new ReplaceOptions { IsUpsert = true });
        }

        return mapper.ToModel(entity);
    }
}
