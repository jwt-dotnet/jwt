#if NET8_0_OR_GREATER
using System.Text.Json.Serialization;

namespace JWT.Tests.Models
{
    [JsonSerializable(typeof(Customer))]
    internal sealed partial class CustomerJsonSerializerContext : JsonSerializerContext
    {
    }
}
#endif
