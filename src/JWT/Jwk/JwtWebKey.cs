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

        /// <summary>
        /// The "kty" parameter which defines key type which is defined by RFC7518 specification.
        /// Valid values are "EC" (Elliptic Curve), "RSA" and "oct" (octet sequence used to represent symmetric keys)
        /// </summary>
        [JsonProperty("kty")]
#if MODERN_DOTNET
        [JsonPropertyName("kty")]
#endif
        public string KeyType { get; set; }

        /// <summary>
        /// The "kid" parameter which defines key id
        /// </summary>
        [JsonProperty("kid")]
#if MODERN_DOTNET
        [JsonPropertyName("kid")]
#endif
        public string KeyId { get; set; }

        /// <summary>
        /// The "n" (modulus) parameter contains the modulus value for the RSA public key. It is represented as a Base64urlUInt-encoded value.
        /// <see cref="KeyType"/> ("kty") must be "RSA"
        /// </summary>
        [JsonProperty("n")]
#if MODERN_DOTNET
        [JsonPropertyName("n")]
#endif
        public string Modulus { get; set; }

        /// <summary>
        /// The "e" (exponent) parameter contains the exponent value for the RSA public key. It is represented as a Base64urlUInt-encoded value.
        /// <see cref="KeyType"/> ("kty") must be "RSA"
        /// </summary>
        [JsonProperty("e")]
#if MODERN_DOTNET
        [JsonPropertyName("e")]
#endif
        public string Exponent { get; set; }

        /// <summary>
        /// The "p" parameter which represents a First Prime Factor for RSA algorithms
        /// </summary>
        [JsonProperty("p")]
#if MODERN_DOTNET
        [JsonPropertyName("p")]
#endif
        public string FirstPrimeFactor { get; set; }

        /// <summary>
        /// The "q" parameter which represents a Second Prime Factor exponent for RSA algorithms
        /// </summary>
        [JsonProperty("q")]
#if MODERN_DOTNET
        [JsonPropertyName("q")]
#endif
        public string SecondPrimeFactor { get; set; }

        /// <summary>
        /// The "dp" parameter which represents a First Factor CRT Exponent for RSA algorithms
        /// </summary>
        [JsonProperty("dp")]
#if MODERN_DOTNET
        [JsonPropertyName("dp")]
#endif
        public string FirstFactorCRTExponent { get; set; }

        /// <summary>
        /// The "dq" parameter which represents a Second Factor CRT Exponent for RSA algorithms
        /// </summary>
        [JsonProperty("dq")]
#if MODERN_DOTNET
        [JsonPropertyName("dq")]
#endif
        public string SecondFactorCRTExponent { get; set; }

        /// <summary>
        /// The "qi" parameter which represents a First CRT Coefficient for RSA algorithms
        /// </summary>
        [JsonProperty("qi")]
#if MODERN_DOTNET
        [JsonPropertyName("qi")]
#endif
        public string FirstCRTCoefficient { get; set; }

        /// <summary>
        /// The "crv" (curve) parameter identifies the cryptographic curve used with the key. RFC7518 defines the following valid values:
        /// "P-256", "P-384", "P-521" <see cref="KeyType"/> ("kty") must be "EC"
        /// </summary>
        [JsonProperty("crv")]
#if MODERN_DOTNET
        [JsonPropertyName("crv")]
#endif
        public string EllipticCurveType { get; set; }

        /// <summary>
        /// The "x" (x coordinate) parameter contains the x coordinate for the Elliptic Curve point.  It is represented as the base64url encoding of
        /// the octet string representation of the coordinate. <see cref="KeyType"/> ("kty") must be "EC"
        /// </summary>
        [JsonProperty("x")]
#if MODERN_DOTNET
        [JsonPropertyName("x")]
#endif
        public string EllipticCurveX { get; set; }

        /// <summary>
        /// The "y" (y coordinate) parameter contains the y coordinate for the Elliptic Curve point.  It is represented as the base64url encoding of
        /// the octet string representation of the coordinate. <see cref="KeyType"/> ("kty") must be "EC"
        /// </summary>
        [JsonProperty("y")]
#if MODERN_DOTNET
        [JsonPropertyName("y")]
#endif
        public string EllipticCurveY { get; set; }

        /// <summary>
        /// The "d" parameter. If <see cref="KeyType"/> ("kty") is "EC" then it represents a
        /// private key for the Elliptic Curve algorithm. If <see cref="KeyType"/> ("kty") is
        /// "RSA" then it represents a private exponent parameter value
        /// </summary>
        [JsonProperty("d")]
#if MODERN_DOTNET
        [JsonPropertyName("d")]
#endif
        public string D { get; set; }

        /// <summary>
        /// The "k" (key value) parameter contains the value of the symmetric (or other single-valued) key.  It is represented as the base64url
        /// encoding of the octet sequence containing the key value. <see cref="KeyType"/> ("kty") must be "oct"
        /// </summary>
        [JsonProperty("k")]
#if MODERN_DOTNET
        [JsonPropertyName("k")]
#endif
        public string SymmetricKey { get; set; }
    }
}