#if SYSTEM_TEXT_JSON
using JsonProperty = System.Text.Json.Serialization.JsonPropertyNameAttribute;
#elif NEWTONSOFT_JSON
using Newtonsoft.Json;
#endif

namespace JWT.Builder
{
    /// <summary>
    /// JSON header model with predefined parameter names specified by RFC 7515, see https://tools.ietf.org/html/rfc7515
    /// </summary>
    public class JwtHeader
    {
        [JsonProperty("typ")]
        public string Type { get; set; }

        [JsonProperty("cty")]
        public string ContentType { get; set; }

        [JsonProperty("alg")]
        public string Algorithm { get; set; }

        [JsonProperty("kid")]
        public string KeyId { get; set; }

        [JsonProperty("x5u")]
        public string X5u { get; set; }

        [JsonProperty("x5c")]
        public string[] X5c { get; set; }

        [JsonProperty("x5t")]
        public string X5t { get; set; }
    }
}