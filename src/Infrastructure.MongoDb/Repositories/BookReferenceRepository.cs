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
    /// Matches against every (title, year, author) combination ever confirmed for a reference, not just its canonical one - see <see cref="ReferenceAliasQueries"/> for the shared query.
    /// </summary>
    public async Task<BookReferenceModel?> FindByTitleYearAsync(string title, int? year, string author)
    {
        var entity = await ReferenceAliasQueries.FindByTitleYearCreatorAsync(Collection, title, year, author);
        return entity is null ? null : mapper.ToModel(entity);
    }

    /// <summary>
    /// The year-agnostic tier, and the one that carries most of this domain's local matching: a work is reprinted under as many years as it has printings, so a tenant's year routinely names an edition no alias was ever confirmed under.
    /// Ambiguity is refused rather than guessed at - two works can genuinely share a title and an author's name.
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
        // No canonical-alias safety net here, deliberately: a book is identified by title + author (or an ISBN), and this model carries only AuthorReferenceId - a dedup'd link, never the author's name - so there is nothing to build a complete key from.
        // It used to add the (title, year) pair anyway, which wrote a creator-less alias onto every book reference ever upserted: unreachable by the creator-bearing lookups, and exactly the half-key ReferenceAliasRule refuses.
        // The Resolve/Refresh paths add a proper alias through ReferenceAliasRule.TitleAndCreatorWithYear before calling this.
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
