using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-256
    /// </summary>
    public sealed class HMACSHA256Algorithm : HMACSHAAlgorithm
    {
        public HMACSHA256Algorithm()
        {
        }

        internal HMACSHA256Algorithm(byte[] key) : base(key)
        {   
        }

        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS256);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA256(key);
    }
}