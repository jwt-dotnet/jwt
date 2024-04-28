#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
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
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [System.Text.Json.Serialization.JsonConstructor]
        public JwtHeader()
        {
        }
#endif
        [JsonProperty("typ")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("typ")]
#endif
        public string Type { get; set; }

        [JsonProperty("cty")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("cty")]
#endif
        public string ContentType { get; set; }

        [JsonProperty("alg")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("alg")]
#endif
        public string Algorithm { get; set; }

        [JsonProperty("kid")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("x5u")]
#endif
        public string X5u { get; set; }

        [JsonProperty("x5c")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("x5c")]
#endif
        public string[] X5c { get; set; }

        [JsonProperty("x5t")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("x5t")]
#endif
        public string X5t { get; set; }
    }
}
