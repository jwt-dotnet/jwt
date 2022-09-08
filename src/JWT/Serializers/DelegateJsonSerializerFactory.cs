using System;

﻿namespace JWT.Serializers
{
    internal sealed class DefaultJsonSerializerFactory : IJsonSerializerFactory
    {
        private readonly Func<IJsonSerializer> _factory;

        public DelegateJsonSerializerFactory(IJsonSerializer jsonSerializer) :
            this(() => jsonSerializer)
        {
            if (jsonSerializer is null)
                 throw new ArgumentNullException(nameof(factory));
        }

        public DelegateJsonSerializerFactory(IJsonSerializerFactory factory) :
            this(() => factory.Create())
        {
            if (factory is null)
                 throw new ArgumentNullException(nameof(factory));
        }

        public DelegateJsonSerializerFactory(Func<IJsonSerializer> factory) :
            _factory = factory ?? throw new ArgumentNullException(nameof(factory));

        public IJsonSerializer CreateSerializer() =>
            _factory();
    }
}
