namespace SiliconBackOffice.Data;

public class UserAddress
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string AddressLine_1 { get; set; } = null!;
    public string? AddressLine_2 { get; set; }
    public string PostalCode { get; set; } = null!;
    public string City { get; set; } = null!;
}