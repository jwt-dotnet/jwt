namespace JWT
{
    /// <summary>
    /// JwtValidator interface.
    /// </summary>
    public interface IJwtValidator
    {
        /// <summary>
        /// Given the JWT, verifies it.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON).</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signature</param>
        /// <exception cref="SignatureVerificationException">The signature is invalid.</exception>
        /// <exception cref="TokenExpiredException">The token has expired.</exception>
        void Validate(string payloadJson, string decodedCrypto, string decodedSignature);
    }
}