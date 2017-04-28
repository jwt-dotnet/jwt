using System.Collections.Generic;

namespace JWT
{
    /// <summary>
    /// JwtEncoder interface.
    /// </summary>
    public interface IJwtEncoder
    {
        /// <summary>
        /// Encodes the paygiven with the provided key.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <returns></returns>
        string Encode(object payload, string key);

        /// <summary>
        /// Creates a JWT given a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key used to sign the token.</param>
        /// <returns>The generated JWT.</returns>
        string Encode(object payload, byte[] key);

        /// <summary>
        /// Creates a JWT given a set of arbitrary extra headers, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers.</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <returns>The generated JWT.</returns>
        string Encode(IDictionary<string, object> extraHeaders, object payload, string key);

        /// <summary>
        /// Creates a JWT given a header, a payload, the signing key, and the algorithm to use.
        /// </summary>
        /// <param name="extraHeaders">An arbitrary set of extra headers. Will be augmented with the standard "typ" and "alg" headers.</param>
        /// <param name="payload">An arbitrary payload (must be serializable to JSON).</param>
        /// <param name="key">The key bytes used to sign the token.</param>
        /// <returns>The generated JWT.</returns>
        string Encode(IDictionary<string, object> extraHeaders, object payload, byte[] key);
    }
}