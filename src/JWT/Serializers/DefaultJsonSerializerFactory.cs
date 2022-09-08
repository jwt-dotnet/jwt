namespace JWT.Serializers
{
    public sealed class DefaultJsonSerializerFactory : IJsonSerializerFactory
    {
        private readonly IJsonSerializer _jsonSerializer;

        public DefaultJsonSerializerFactory()
        {
#if MODERN_DOTNET
            _jsonSerializer = new SystemTextSerializer();
#else
            _jsonSerializer = new JsonNetSerializer();
#endif
        }

        public IJsonSerializer Create() =>
            _jsonSerializer;
    }
}
