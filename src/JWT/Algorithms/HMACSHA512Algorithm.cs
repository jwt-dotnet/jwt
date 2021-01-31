using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public sealed class HMACSHA512Algorithm : IJwtAlgorithm
    {
        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using var sha = new HMACSHA512(key);
            return sha.ComputeHash(bytesToSign);
        }

        /// <inheritdoc />
        public string Name => JwtAlgorithmName.HS512.ToString();

        public string HashAlgorithm =>
#if NET35 || NET40
            HashAlgorithmName.SHA512;
#else
            HashAlgorithmName.SHA512.Name;
#endif
    }
}