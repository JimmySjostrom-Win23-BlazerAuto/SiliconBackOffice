using System.Diagnostics;

namespace SiliconBackOffice.Models;

public class CourseCardModel
{
	public string? Id { get; set; } = null!;
	public bool IsBestseller { get; set; }
	public string? ImageUri { get; set; }
	public string? Title { get; set; }
	public string? Author { get; set; }
	public string? Price { get; set; }
	public string? DiscountPrice { get; set; }
	public string? Hours { get; set; }
	public string? LikesInProcent { get; set; }
	public string? LikesInNumbers { get; set; }
}