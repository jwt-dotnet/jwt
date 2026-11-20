using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-256
    /// </summary>
    public sealed class HMACSHA256Algorithm : HMACSHAAlgorithm
    {
        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS256);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA256(key);

#if NET8_0_OR_GREATER
        internal override bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            HMACSHA256.TryHashData(key, bytesToSign, destination, out bytesWritten);
#endif
    }
}