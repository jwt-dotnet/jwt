namespace JWT.Algorithms
{
    /// <summary>
    /// Enum representing the various Jwt Hash Algorithms.
    /// </summary>
    public enum JwtAlgorithmName
    {
        /// <summary>
        /// HMAC using SHA-256
        /// </summary>
        HS256,

        /// <summary>
        /// HMAC using SHA-384
        /// </summary>
        HS384,

        /// <summary>
        /// HMAC using SHA-512
        /// </summary>
        HS512,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256
        /// </summary>
        RS256,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-384
        /// </summary>
        RS384,

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-512
        /// </summary>
        RS512,

        /// <summary>
        /// ECDSA P-256 using SHA-256
        /// </summary>
        ES256,

        /// <summary>
        /// ECDSA P-256 using SHA-384
        /// </summary>
        ES384
    }
}