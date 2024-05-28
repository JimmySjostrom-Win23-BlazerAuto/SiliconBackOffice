using System.Text.Json;
using System.Text.Json.Serialization;

namespace SiliconBackOffice.Models;

public class DynamicGraphQLResponse
{
	[JsonPropertyName("data")]
	public JsonElement Data { get; set; }
}