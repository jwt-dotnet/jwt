namespace JWT
{
    /// <summary>
    /// Represents a JWT decoder.
    /// </summary>
    public interface IJwtDecoder
    {
        #region DecodeHeader

        /// <summary>
        /// Given a JWT, decodes it and return the header.
        /// </summary>
        /// <param name="token">The JWT</param>
        string DecodeHeader(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the header as an object.
        /// </summary>
        /// <param name="token">The JWT</param>
        T DecodeHeaderToObject<T>(string token);

        #endregion

        #region Decode

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="jwt">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(JwtParts jwt);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="key">The key bytes that were used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, byte[] key, bool verify);

        /// <summary>
        /// Given a JWT, decodes it and return the payload.
        /// </summary>
        /// <param name="token">The JWT</param>
        /// <param name="keys">The keys bytes provided which one of them was used to sign the JWT</param>
        /// <param name="verify">Whether to verify the signature (default is true)</param>
        /// <returns>A string containing the JSON payload</returns>
        string Decode(string token, byte[][] keys, bool verify);

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
        T DecodeToObject<T>(string token, byte[][] keys, bool verify);

        #endregion
    }
}