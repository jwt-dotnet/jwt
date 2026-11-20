#if NET8_0_OR_GREATER
using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Signs and verifies spans with the built-in algorithms, which do it without allocating.
    /// </summary>
    internal static class SpanAlgorithmExtensions
    {
        /// <summary>
        /// Large enough for HMAC, ECDSA and RSA signatures with keys up to 4096 bits.
        /// </summary>
        public const int MaxStackSignatureSize = 512;

        /// <summary>
        /// Returns whether the algorithm is a built-in one that can sign and verify spans.
        /// </summary>
        /// <remarks>
        /// Classes deriving from <see cref="HMACSHAAlgorithm" />, <see cref="RSAlgorithm" /> or <see cref="ECDSAAlgorithm" />
        /// in other assemblies can override how data is signed or verified, so they keep using arrays.
        /// </remarks>
        public static bool CanUseSpans(this IJwtAlgorithm algorithm) =>
            algorithm is HMACSHAAlgorithm or RSAlgorithm or ECDSAAlgorithm &&
            algorithm.GetType().Assembly == typeof(SpanAlgorithmExtensions).Assembly;

        /// <summary>
        /// Signs the data into <paramref name="buffer" />, or into a new array if the buffer is too small.
        /// </summary>
        public static ReadOnlySpan<byte> Sign(this IJwtAlgorithm algorithm, byte[] key, ReadOnlySpan<byte> bytesToSign, Span<byte> buffer) =>
            TrySign(algorithm, key, bytesToSign, buffer, out var bytesWritten) ?
                buffer.Slice(0, bytesWritten) :
                algorithm.Sign(key, bytesToSign.ToArray());

        /// <summary>
        /// Same as <see cref="IAsymmetricAlgorithm.Verify(byte[], byte[])" /> without arrays.
        /// </summary>
        public static bool Verify(this IAsymmetricAlgorithm algorithm, ReadOnlySpan<byte> bytesToSign, ReadOnlySpan<byte> signature) =>
            algorithm switch
            {
                RSAlgorithm rsa => rsa.VerifyData(bytesToSign, signature),
                ECDSAAlgorithm ecdsa => ecdsa.VerifyData(bytesToSign, signature),
                _ => algorithm.Verify(bytesToSign.ToArray(), signature.ToArray())
            };

        private static bool TrySign(IJwtAlgorithm algorithm, byte[] key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten)
        {
            switch (algorithm)
            {
                case HMACSHAAlgorithm hmac:
                    return hmac.TrySign(key, bytesToSign, destination, out bytesWritten);
                case RSAlgorithm rsa:
                    return rsa.TrySignData(bytesToSign, destination, out bytesWritten);
                case ECDSAAlgorithm ecdsa:
                    return ecdsa.TrySignData(bytesToSign, destination, out bytesWritten);
                default:
                    bytesWritten = 0;
                    return false;
            }
        }
    }
}
#endif
