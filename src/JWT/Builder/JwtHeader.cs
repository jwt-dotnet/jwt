#if MODERN_DOTNET
using System.Text.Json.Serialization;
#endif

using Newtonsoft.Json;

namespace JWT.Builder
{
    /// <summary>
    /// JSON header model with predefined parameter names specified by RFC 7515, see https://tools.ietf.org/html/rfc7515
    /// </summary>
    public class JwtHeader
    {
#if MODERN_DOTNET
        [System.Text.Json.Serialization.JsonConstructor]
        public JwtHeader()
        {
        }
#endif        
        [JsonProperty("typ")]
#if MODERN_DOTNET
        [JsonPropertyName("typ")]
#endif
        public string Type { get; set; }

        [JsonProperty("cty")]
#if MODERN_DOTNET
        [JsonPropertyName("cty")]
#endif
        public string ContentType { get; set; }

        [JsonProperty("alg")]
#if MODERN_DOTNET
        [JsonPropertyName("alg")]
#endif
        public string Algorithm { get; set; }

        [JsonProperty("kid")]
#if MODERN_DOTNET
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
#if MODERN_DOTNET
        [JsonPropertyName("x5u")]
#endif
        public string X5u { get; set; }

        [JsonProperty("x5c")]
#if MODERN_DOTNET
        [JsonPropertyName("x5c")]
#endif
        public string[] X5c { get; set; }

        [JsonProperty("x5t")]
#if MODERN_DOTNET
        [JsonPropertyName("x5t")]
#endif
        public string X5t { get; set; }
    }
}
