namespace KeepTrack.Domain.Models;

public class CarModel
{
    public string Id { get; set; }

    public string OwnerId { get; set; }

    public string Name { get; set; }

    public override string ToString()
    {
        return $"Car ID=\"{Id}\", Name=\"{Name}\"";
    }
}
