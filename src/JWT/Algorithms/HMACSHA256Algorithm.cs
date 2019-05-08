using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-256
    /// </summary>
    public sealed class HMACSHA256Algorithm : IJwtAlgorithm
    {
        /// <inheritdoc />
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA256(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.HS256.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric => false;
    }
}