using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public sealed class HMACSHA384Algorithm : IJwtAlgorithm
    {
        /// <summary>
        /// Signs the provided byte array with the provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data.</param>
        /// <param name="bytesToSign">The data to sign.</param>
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA384(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        /// <summary>
        /// The algorithm name.
        /// </summary>
        public string Name => JwtHashAlgorithm.HS384.ToString();
    }
}