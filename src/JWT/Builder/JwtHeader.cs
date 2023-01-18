#if NETSTANDARD2_0 || NET6_0
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
        [JsonProperty("typ")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("typ")]
#endif
        public string Type { get; set; }

        [JsonProperty("cty")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("cty")]
#endif
        public string ContentType { get; set; }

        [JsonProperty("alg")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("alg")]
#endif
        public string Algorithm { get; set; }

        [JsonProperty("kid")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("x5u")]
#endif
        public string X5u { get; set; }

        [JsonProperty("x5c")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("x5c")]
#endif
        public string[] X5c { get; set; }

        [JsonProperty("x5t")]
#if NETSTANDARD2_0 || NET6_0
        [JsonPropertyName("x5t")]
#endif
        public string X5t { get; set; }
    }
}