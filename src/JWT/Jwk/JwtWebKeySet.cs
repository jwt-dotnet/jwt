
using System.Collections.Generic;
using Newtonsoft.Json;

#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
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
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonConstructor]
        public JwtWebKeySet()
        {
        } 
#endif

        [JsonProperty("keys")]
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
        [JsonPropertyName("keys")]
#endif
        public IEnumerable<JwtWebKey> Keys { get; set; } = null!;
    }
}
