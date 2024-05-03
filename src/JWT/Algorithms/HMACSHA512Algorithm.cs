using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public sealed class HMACSHA512Algorithm : HMACSHAAlgorithm
    {   
        public HMACSHA512Algorithm()
        {
        }

        internal HMACSHA512Algorithm(byte[] key) : base(key)
        {
        }

        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS512);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA512(key);
    }
}