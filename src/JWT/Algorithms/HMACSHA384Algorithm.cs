using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-384
    /// </summary>
    public sealed class HMACSHA384Algorithm : HMACSHAAlgorithm
    {
        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS384);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA384;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA384(key);

#if NET8_0_OR_GREATER
        internal override bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            HMACSHA384.TryHashData(key, bytesToSign, destination, out bytesWritten);
#endif
    }
}