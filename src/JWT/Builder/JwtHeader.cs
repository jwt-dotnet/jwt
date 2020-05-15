using Newtonsoft.Json;
#if SYSTEMTEXTJSON
using System.Text.Json.Serialization;
#endif

namespace JWT.Builder
{
    /// <summary>
    /// JSON header model with predefined parameter names specified by RFC 7515, see https://tools.ietf.org/html/rfc7515
    /// </summary>
    public class JwtHeader
    {
        [JsonProperty("typ")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("typ")]
#endif
        public string Type { get; set; }

        [JsonProperty("cty")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("cty")]
#endif
        public string ContentType { get; set; }

        [JsonProperty("alg")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("alg")]
#endif
        public string Algorithm { get; set; }

        [JsonProperty("kid")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("x5u")]
#endif
        public string X5u { get; set; }

        [JsonProperty("x5c")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("x5c")]
#endif
        public string X5c { get; set; }

        [JsonProperty("x5t")]
#if SYSTEMTEXTJSON
        [JsonPropertyName("x5t")]
#endif
        public string X5t { get; set; }
    }
}