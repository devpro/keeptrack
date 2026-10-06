using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Keeptrack.Common.System;
using Keeptrack.Domain.Models;
using Keeptrack.Domain.Repositories;
using Keeptrack.Domain.Services;
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

    /// <summary>
    /// Matches every (title, year, author) combination confirmed for a reference, not only its canonical one (see <see cref="ReferenceAliasQueries"/>).
    /// </summary>
    public async Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author)
    {
        var entity = await ReferenceAliasQueries.FindByTitleYearCreatorAsync(Collection, title, year, author);
        return entity is null ? null : mapper.ToModel(entity);
    }

    /// <summary>
    /// The tier ignoring the year, which carries most of this domain's local matching.
    /// A work is reprinted under as many years as it has printings, so a tenant's year often names an edition no alias was confirmed under.
    /// Ambiguity is refused rather than guessed, since two works can share a title and an author's name.
    /// </summary>
    public async Task<BookReferenceModel?> FindByTitleAsync(string title, string author)
    {
        var entity = await ReferenceAliasQueries.FindByTitleCreatorAsync(Collection, title, author, refuseAmbiguous: true);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<BookReferenceModel?> FindByIsbnAsync(string isbn)
    {
        var entity = await ReferenceAliasQueries.FindByIsbnAsync(Collection, isbn);
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<BookReferenceModel?> FindByExternalIdAsync(string provider, string externalId)
    {
        var filter = Builders<BookReference>.Filter.Eq($"external_ids.{provider}", externalId);
        var entity = await Collection.Find(filter).FirstOrDefaultAsync();
        return entity is null ? null : mapper.ToModel(entity);
    }

    public async Task<List<BookReferenceModel>> FindStaleAsync(DateTime cutoff, int limit)
    {
        var entities = await ReferenceStalenessQueries.FindStaleAsync(Collection, x => x.LastEnrichedAt, cutoff, limit);
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<List<BookReferenceModel>> FindAllAsync()
    {
        var entities = await Collection.Find(FilterDefinition<BookReference>.Empty).ToListAsync();
        return entities.Select(mapper.ToModel).ToList();
    }

    public async Task<BookReferenceModel> UpsertAsync(BookReferenceModel model)
    {
        model.TitleNormalized = TitleNormalizer.Normalize(model.Title);
        // No canonical-alias safety net: a book is its title and author, or an ISBN, and this model carries only AuthorReferenceId, never the name, so a complete key cannot be built here.
        // The resolve and refresh paths add the alias through ReferenceAliasRule.TitleAndCreatorWithYear before calling this.
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

    public async Task DeleteAsync(string id)
    {
        await Collection.DeleteOneAsync(x => x.Id == id);
    }
}
