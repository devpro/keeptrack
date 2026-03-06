using System.Threading.Tasks;
using KeepTrack.Domain.Models;

namespace KeepTrack.Domain.Repositories;

public interface ICarRepository
{
    Task<CarModel?> FindOneAsync(string id);
}
