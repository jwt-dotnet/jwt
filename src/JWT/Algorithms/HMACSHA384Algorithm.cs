using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public sealed class HMACSHA384Algorithm : HMACSHAAlgorithm
    {
        public HMACSHA384Algorithm()
        {
            
        }

        internal HMACSHA384Algorithm(byte[] key) : base(key)
        {
            
        }

        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS384);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA384;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA384(key);
    }
}