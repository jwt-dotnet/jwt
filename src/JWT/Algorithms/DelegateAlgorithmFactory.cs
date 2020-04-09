using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements <see href="IAlgorithmFactory" /> by returning the supplied <see href="IJwtAlgorithm" /> while ignoring parameters.
    /// </summary>
    public sealed class DelegateAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<IJwtAlgorithm> _algFactory;

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied delegate to an algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(Func<IJwtAlgorithm> algFactory) =>
            _algFactory = algFactory ?? throw new ArgumentNullException(nameof(algFactory));

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(IJwtAlgorithm algorithm)
        {
            if (algorithm is null)
                throw new ArgumentNullException(nameof(algorithm));

            _algFactory = () => algorithm;
        }

        /// <inheritdoc />
        public IJwtAlgorithm Create(JwtDecoderContext context) =>
            _algFactory();
    }
}