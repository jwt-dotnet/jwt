using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public sealed class HMACSHA384Algorithm : IJwtAlgorithm
    {
        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using var sha = new HMACSHA384(key);
            return sha.ComputeHash(bytesToSign);
        }

        /// <inheritdoc />
        public string Name => JwtAlgorithmName.HS384.ToString();

        public string HashAlgorithm =>
#if NET35 || NET40
            HashAlgorithmName.SHA384;
#else
            HashAlgorithmName.SHA384.Name;
#endif
    }
}