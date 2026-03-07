namespace KeepTrack.Domain.Models;

public class CarModel
{
    public string Id { get; set; } = null!;

    public required string OwnerId { get; set; }

    public required string Name { get; set; }

    public override string ToString()
    {
        return $"Car ID=\"{Id}\", Name=\"{Name}\"";
    }
}
