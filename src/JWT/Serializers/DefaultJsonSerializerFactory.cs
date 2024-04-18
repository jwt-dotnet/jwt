namespace JWT.Serializers
{
    public sealed class DefaultJsonSerializerFactory : IJsonSerializerFactory
    {
        private readonly IJsonSerializer _jsonSerializer;

        public DefaultJsonSerializerFactory()
        {
#if NET462_OR_GREATER || NET6_0_OR_GREATER || NETSTANDARD2_0_OR_GREATER
            _jsonSerializer = new SystemTextSerializer();
#else
            _jsonSerializer = new JsonNetSerializer();
#endif
        }

        public IJsonSerializer Create() =>
            _jsonSerializer;
    }
}
