using System;
using System.Security.Cryptography;

namespace JWT.Algorithms
{
    /// <summary>
    /// HMAC using SHA-512
    /// </summary>
    public sealed class HMACSHA512Algorithm : HMACSHAAlgorithm
    {
        /// <inheritdoc />
        public override string Name => nameof(JwtAlgorithmName.HS512);

        /// <inheritdoc />
        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        protected override HMAC CreateAlgorithm(byte[] key) => new HMACSHA512(key);

#if NET8_0_OR_GREATER
        internal override bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            HMACSHA512.TryHashData(key, bytesToSign, destination, out bytesWritten);
#endif
    }
}