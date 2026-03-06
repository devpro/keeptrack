using KeepTrack.Domain.Models;
using KeepTrack.Domain.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KeepTrack.WebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/car-history")]
public class CarHistoryController(IMapper mapper, ICarHistoryRepository carHistoryRepository)
    : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(200, Type = typeof(List<CarHistoryDto>))]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Get(string carId)
    {
        if (string.IsNullOrEmpty(carId))
        {
            return BadRequest();
        }

        var models = await carHistoryRepository.FindAllAsync(carId, GetUserId());
        return Ok(mapper.Map<List<CarHistoryDto>>(models));
    }

    [HttpGet("{id}", Name = "GetCarHistoryById")]
    [ProducesResponseType(200, Type = typeof(CarHistoryDto))]
    [ProducesResponseType(400)]
    [ProducesResponseType(404)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> GetById(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var model = await carHistoryRepository.FindOneAsync(id, GetUserId());
        if (model == null)
        {
            return NotFound();
        }

        return Ok(mapper.Map<CarHistoryDto>(model));
    }

    [HttpPost]
    [ProducesResponseType(201)]
    public async Task<IActionResult> Post([FromBody] CarHistoryDto dto)
    {
        var input = mapper.Map<CarHistoryModel>(dto);
        input.OwnerId = GetUserId();
        var model = await carHistoryRepository.CreateAsync(input);
        return CreatedAtRoute("GetCarHistoryById", new { id = model.Id }, mapper.Map<CarHistoryDto>(model));
    }

    [HttpPut("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Put(string id, [FromBody] CarHistoryDto dto)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        var input = mapper.Map<CarHistoryModel>(dto);
        input.OwnerId = GetUserId();
        await carHistoryRepository.UpdateAsync(id, input, GetUserId());
        return NoContent();
    }

    [HttpDelete("{id}")]
    [ProducesResponseType(204)]
    [ProducesResponseType(400)]
    [ProducesResponseType(500)]
    public async Task<IActionResult> Delete(string id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return BadRequest();
        }

        await carHistoryRepository.DeleteAsync(id, GetUserId());
        return NoContent();
    }

    /// <summary>
    /// Get authenticated user id.
    /// </summary>
    /// <returns></returns>
    private string GetUserId()
    {
        var userId = User.Claims.FirstOrDefault(x => x.Type == "user_id")?.Value;
        return string.IsNullOrEmpty(userId) ? throw new UnauthorizedAccessException() : userId;
    }
}
