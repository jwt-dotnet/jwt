using System.Collections.Generic;

namespace JWT
{
    /// <summary>
    /// Represents a JWT decoder.
    /// </summary>
    public interface IJwtDecoder
    {
        #region Decode

        /// <summary>
        /// Given a JWT, decodes it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, string key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, string[] keys, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key bytes that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the JSON payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys bytes provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, IReadOnlyCollection<byte[]> keys, bool verify);

        #endregion

        #region IDictionary<string, object> DecodeToObject
        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>An object representing the payload</returns>
        IDictionary<string, object> DecodeToObject(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        IDictionary<string, object> DecodeToObject(string token, string key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The key which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        IDictionary<string, object> DecodeToObject(string token, string[] keys, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        IDictionary<string, object> DecodeToObject(string token, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The key which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        IDictionary<string, object> DecodeToObject(string token, IReadOnlyCollection<byte[]> keys, bool verify);

        #endregion

        #region T DecodeToObject<T>

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="token">The JWT</param>
        /// <returns>An object representing the payload</returns>
        T DecodeToObject<T>(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        T DecodeToObject<T>(string token, string key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        T DecodeToObject<T>(string token, string[] keys, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key that was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        T DecodeToObject<T>(string token, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload as an object.
        /// </summary>
        /// <typeparam name="T">The type to return</typeparam>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>An object representing the payload</returns>
        /// <exception cref="SignatureVerificationException">Thrown if the verify parameter was true and the signature was NOT valid or if the JWT was signed with an unsupported algorithm</exception>
        /// <exception cref="TokenExpiredException">Thrown if the verify parameter was true and the token has an expired exp claim</exception>
        T DecodeToObject<T>(string token, IReadOnlyCollection<byte[]> keys, bool verify);

        #endregion
    }
}