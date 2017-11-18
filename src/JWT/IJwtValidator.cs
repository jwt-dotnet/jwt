namespace JWT
{
    /// <summary>
    /// Represents a JWT validTor.
    /// </summary>
    public interface IJwtValidTor
    {
        /// <summary>
        /// Given the JWT, verifies its signature correctness.
        /// </summary>
        /// <param name="payloadJson">>An arbitrary payload (already serialized to JSON).</param>
        /// <param name="decodedCrypto">Decoded body</param>
        /// <param name="decodedSignature">Decoded signature</param>
        /// <exception cref="SignatureVerificationException">The signature is invalid.</exception>
        /// <exception cref="TokenExpiredException">The token has expired.</exception>
        void Validate(string payloadJson, string decodedCrypto, string decodedSignature);
    }
}