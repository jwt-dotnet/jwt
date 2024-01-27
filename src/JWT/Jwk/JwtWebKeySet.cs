
using System.Collections.Generic;
using Newtonsoft.Json;

#if MODERN_DOTNET
using System.Text.Json.Serialization;
#endif

namespace JWT.Jwk
{
    /// <summary>
    /// A JWK Set JSON data structure that represents a set of JSON Web Keys
    /// specifed by RFC 7517, see https://datatracker.ietf.org/doc/html/rfc7517
    /// </summary>
    public sealed class JwtWebKeySet
    {
#if MODERN_DOTNET
        [System.Text.Json.Serialization.JsonConstructor]
        public JwtWebKeySet()
        {

        } 
#endif

        [JsonProperty("keys")]
#if MODERN_DOTNET
        [JsonPropertyName("keys")]
#endif
        public IEnumerable<JwtWebKey> Keys { get; set; } = null!;
    }
}