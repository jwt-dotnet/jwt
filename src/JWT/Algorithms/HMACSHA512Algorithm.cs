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
            using (var sha = new HMACSHA512(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        /// <inheritdoc />
        public string Name => JwtHashAlgorithm.HS512.ToString();

        /// <inheritdoc />
        public bool IsAsymmetric => false;
    }
}