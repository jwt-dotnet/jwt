using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements <see href="IAlgorithmFactory" /> by returning the supplied algorithm.
    /// </summary>
    public sealed class DelegateAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<IJwtAlgorithm> _algFactory;

        public DelegateAlgorithmFactory(Func<IAlgorithm> algFactory) =>
            _algFactory = algFactory;

        public DelegateAlgorithmFactory(IJwtAlgorithm algorithm)
            : this(() => algorithm)
        {
        }

        /// <inheritdoc />
        public IJwtAlgorithm Create(IJwtAlgorithm algorithm) =>
            _algFactory();
    }
}
