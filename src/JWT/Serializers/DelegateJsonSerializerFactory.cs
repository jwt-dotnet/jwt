using System;

namespace JWT.Serializers
{
    internal sealed class DelegateJsonSerializerFactory : IJsonSerializerFactory
    {
        private readonly Func<IJsonSerializer> _factory;

        /// <summary>
        /// Creates an instance of <see cref="DelegateJsonSerializerFactory" /> with supplied JSON serializer.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateJsonSerializerFactory(IJsonSerializer jsonSerializer) :
            this(() => jsonSerializer)
        {
            if (jsonSerializer is null)
                throw new ArgumentNullException(nameof(jsonSerializer));
        }

        /// <summary>
        /// Creates an instance of <see cref="DelegateJsonSerializerFactory" /> with supplied serializer JSON serializer factory.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateJsonSerializerFactory(IJsonSerializerFactory factory) :
            this(() => factory?.Create())
        {
            if (factory is null)
                throw new ArgumentNullException(nameof(factory));
        }

        /// <summary>
        /// Creates an instance of <see cref="DelegateJsonSerializerFactory" /> with supplied delegate to a JSON serializer.
        /// </summary>
        /// <exception cref="ArgumentNullException" />
        public DelegateJsonSerializerFactory(Func<IJsonSerializer> factory) =>
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        public IJsonSerializer Create() =>
            _factory();
    }
}
