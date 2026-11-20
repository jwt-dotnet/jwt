#if NET8_0_OR_GREATER
using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Signs and verifies spans with algorithms whose <see cref="JwtAlgorithm.CanUseSpans" /> is <see langword="true" />.
    /// </summary>
    internal static class SpanAlgorithmExtensions
    {
        /// <summary>
        /// Large enough for HMAC, ECDSA and RSA signatures with keys up to 4096 bits.
        /// </summary>
        public const int MaxStackSignatureSize = 512;

        public static bool CanUseSpans(this IJwtAlgorithm algorithm) =>
            algorithm is JwtAlgorithm { CanUseSpans: true };

        /// <summary>
        /// Signs the data into <paramref name="buffer" />, or into a new array if the buffer is too small.
        /// </summary>
        public static ReadOnlySpan<byte> Sign(this IJwtAlgorithm algorithm, byte[] key, ReadOnlySpan<byte> bytesToSign, Span<byte> buffer) =>
            ((JwtAlgorithm)algorithm).TrySign(key, bytesToSign, buffer, out var bytesWritten) ?
                buffer.Slice(0, bytesWritten) :
                algorithm.Sign(key, bytesToSign.ToArray());

        public static bool Verify(this IAsymmetricAlgorithm algorithm, ReadOnlySpan<byte> bytesToSign, ReadOnlySpan<byte> signature) =>
            ((JwtAlgorithm)algorithm).Verify(bytesToSign, signature);
    }
}
#endif
