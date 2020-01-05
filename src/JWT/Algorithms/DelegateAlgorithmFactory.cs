using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements <see href="IAlgorithmFactory" /> by returning the supplied algorithm.
    /// </summary>
    public sealed class DelegateAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<IAlgorithm> _algFactory;

        public DelegateAlgorithmFactory(Func<IAlgorithm> algFactory) =>
            _algFactory = algFactory;

        public DelegateAlgorithmFactory(IAlgorithm algorithm)
            : this(() => algorithm)
        {
        }

        /// <inheritdoc />
        public IJwtAlgorithm Create(IAlgorithm algorithm) =>
            _algFactory();
    }
}
