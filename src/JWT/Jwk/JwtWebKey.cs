using Newtonsoft.Json;

#if MODERN_DOTNET
using System.Text.Json.Serialization;
#endif

namespace JWT.Jwk
{
    /// <summary>
    /// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key
    /// specifed by RFC 7517, see https://datatracker.ietf.org/doc/html/rfc7517
    /// </summary>
    public sealed class JwtWebKey
    {
#if MODERN_DOTNET
        [System.Text.Json.Serialization.JsonConstructor]
        public JwtWebKey()
        {

        } 
#endif

        [JsonProperty("kty")]
#if MODERN_DOTNET
        [JsonPropertyName("kty")]
#endif
        public string KeyType { get; set; }

        [JsonProperty("kid")]
#if MODERN_DOTNET
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        [JsonProperty("n")]
#if MODERN_DOTNET
        [JsonPropertyName("n")]
#endif
        public string Modulus { get; set; }

        [JsonProperty("e")]
#if MODERN_DOTNET
        [JsonPropertyName("e")]
#endif
        public string Exponent { get; set; }

        [JsonProperty("crv")]
#if MODERN_DOTNET
        [JsonPropertyName("crv")]
#endif
        public string EllipticCurveType { get; set; }

        [JsonProperty("x")]
#if MODERN_DOTNET
        [JsonPropertyName("x")]
#endif
        public string EllipticCurveX { get; set; }

        [JsonProperty("y")]
#if MODERN_DOTNET
        [JsonPropertyName("y")]
#endif
        public string EllipticCurveY { get; set; }

        [JsonProperty("k")]
#if MODERN_DOTNET
        [JsonPropertyName("k")]
#endif
        public string SymmetricKey { get; set; }
    }
}