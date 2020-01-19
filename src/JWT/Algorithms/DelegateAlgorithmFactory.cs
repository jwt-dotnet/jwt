using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements <see href="IAlgorithmFactory" /> by returning the supplied <see href="IJwtAlgorithm" /> while ignoring parameters.
    /// </summary>
    public sealed class DelegateAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<IJwtAlgorithm> _algFactory;

        public DelegateAlgorithmFactory(Func<IJwtAlgorithm> algFactory) =>
            _algFactory = algFactory;

        public DelegateAlgorithmFactory(IJwtAlgorithm algorithm)
            : this(() => algorithm)
        {
        }

        /// <inheritdoc />
        public IJwtAlgorithm Create(string algorithmName) =>
            _algFactory();

        /// <inheritdoc />
        public IJwtAlgorithm Create(JwtHashAlgorithm algorithm) =>
            _algFactory();
    }
}