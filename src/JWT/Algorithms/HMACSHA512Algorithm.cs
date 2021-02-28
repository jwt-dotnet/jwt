using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public sealed class HMACSHA512Algorithm : HMACSHAAlgorithm
    {
        /// <inheritdoc />
        public override string Name => JwtAlgorithmName.HS512.ToString();

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA512(key);
    }
}
