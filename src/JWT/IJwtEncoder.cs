using System;
using System.Collections.Generic;

using static JWT.Internal.EncodingHelper;

namespace JWT
{
    /// <summary>
    /// Represents a JWT encoder.
    /// </summary>
    public interface IJwtEncoder
    {
        /// <summary>
        /// Creates a JWT given a header, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON)</param>
        /// <param name="key">The key bytes used to sign the token</param>
        /// <returns>The generated JWT</returns>
        string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key);
    }

    /// <summary>
    /// Extension methods for <seealso cref="IJwtEncoder" />
    ///</summary>
    public static class JwtEncoderExtensions
    {
        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="encoder">The encoder instance</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON)</param>
        /// <param name="key">The key used to sign the token</param>
        /// <returns>The generated JWT</returns>
        /// <exception cref="ArgumentNullException" />
        public static string Encode(this IJwtEncoder encoder, object payload, string key) =>
            encoder.Encode(null, payload, key is object ? GetBytes(key) : null);

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="encoder">The encoder instance</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON)</param>
        /// <param name="key">The key used to sign the token</param>
        /// <returns>The generated JWT</returns>
        /// <exception cref="ArgumentNullException" />
        public static string Encode(this IJwtEncoder encoder, object payload, byte[] key) =>
            encoder.Encode(null, payload, key);

        /// <summary>
        /// Creates a JWT given a set of arbitrary extra headers, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="encoder">The encoder instance</param>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON)</param>
        /// <param name="key">The key bytes used to sign the token</param>
        /// <returns>The generated JWT</returns>
        /// <exception cref="ArgumentNullException" />
        public static string Encode(this IJwtEncoder encoder, IDictionary<string, object> extraHeaders, object payload, string key) =>
            encoder.Encode(extraHeaders, payload, GetBytes(key));
    }
}