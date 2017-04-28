using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public sealed class HMACSHA512Algorithm : IJwtAlgorithm
    {
        /// <summary>
        /// Signs the provided byte array with the provided key.
        /// </summary>
        /// <param name="key">The key used to sign the data.</param>
        /// <param name="bytesToSign">The data to sign.</param>
        public byte[] Sign(byte[] key, byte[] bytesToSign)
        {
            using (var sha = new HMACSHA512(key))
            {
                return sha.ComputeHash(bytesToSign);
            }
        }

        /// <summary>
        /// The algorithm name.
        /// </summary>
        public string Name => JwtHashAlgorithm.HS512.ToString();
    }
}