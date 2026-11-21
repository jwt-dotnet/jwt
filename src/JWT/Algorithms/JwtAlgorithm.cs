using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Base class of the built-in algorithms.
    /// </summary>
    public abstract class JwtAlgorithm
    {
        private protected JwtAlgorithm()
        {
        }

#if NET8_0_OR_GREATER
        /// <summary>
        /// Gets whether the encoder and decoder can use <see cref="TrySign" /> and <see cref="Verify" /> instead of arrays.
        /// </summary>
        /// <remarks>
        /// Classes deriving from <see cref="RSAlgorithm" /> or <see cref="ECDSAAlgorithm" /> in other assemblies can override how data is signed or verified,
        /// so they keep using arrays.
        /// </remarks>
        internal bool CanUseSpans =>
            this.SupportsSpans &&
            GetType().Assembly == typeof(JwtAlgorithm).Assembly;

        /// <summary>
        /// Gets whether the algorithm implements <see cref="TrySign" />, and <see cref="Verify" /> if it's asymmetric.
        /// </summary>
        private protected virtual bool SupportsSpans => false;

        /// <summary>
        /// Same as <see cref="IJwtAlgorithm.Sign" /> without arrays.
        /// </summary>
        /// <returns><see langword="false" /> if <paramref name="destination" /> is too small.</returns>
        internal virtual bool TrySign(ReadOnlySpan<byte> key, ReadOnlySpan<byte> bytesToSign, Span<byte> destination, out int bytesWritten) =>
            throw new NotSupportedException($"{GetType().Name} doesn't sign spans.");

        /// <summary>
        /// Same as <see cref="IAsymmetricAlgorithm.Verify" /> without arrays.
        /// </summary>
        internal virtual bool Verify(ReadOnlySpan<byte> bytesToSign, ReadOnlySpan<byte> signature) =>
            throw new NotSupportedException($"{GetType().Name} doesn't verify spans.");
#endif
    }
}