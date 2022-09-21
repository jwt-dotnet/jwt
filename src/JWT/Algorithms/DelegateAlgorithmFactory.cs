using System;

namespace JWT.Algorithms
{
    /// <summary>
    /// Implements <see href="IAlgorithmFactory" /> by returning the supplied <see href="IJwtAlgorithm" /> while ignoring parameters.
    /// </summary>
    public sealed class DelegateAlgorithmFactory : IAlgorithmFactory
    {
        private readonly Func<JwtDecoderContext, IJwtAlgorithm> _algFactory;

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied delegate to an algorithm with a context.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(Func<JwtDecoderContext, IJwtAlgorithm> algFactory) =>
            _algFactory = algFactory ?? throw new ArgumentNullException(nameof(algFactory));

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied delegate to an algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(Func<IJwtAlgorithm> algFactory)
            : this(_ => algFactory())
        {
            if (algFactory is null)
                throw new ArgumentNullException(nameof(algFactory));
        }

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied algorithm factory.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(IAlgorithmFactory algFactory) :
            this(c => algFactory?.Create(c))
        {
            if (algFactory is null)
                throw new ArgumentNullException(nameof(algFactory));
        }

        /// <summary>
        /// Creates an instance of <see cref="DelegateAlgorithmFactory" /> with supplied algorithm.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateAlgorithmFactory(IJwtAlgorithm algorithm) :
            this(() => algorithm)
        {
            if (algorithm is null)
                throw new ArgumentNullException(nameof(algorithm));
        }

        /// <inheritdoc />
        public IJwtAlgorithm Create(JwtDecoderContext context) =>
            _algFactory(context);
    }
}
