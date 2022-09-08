namespace JWT.Serializers
{
    internal sealed class DefaultJsonSerializerFactory : IJsonSerializerFactory
    {
        private readonly IJsonSerializer _jsonSerializer;

        public JsonSerializerFactory()
        {
#if MODERN_DOTNET
            _jsonSerializer = new SystemTextSerializer();
#else
            _jsonSerializer = new JsonNetSerializer();
#endif
        }

        public IJsonSerializer CreateSerializer()
        {
            return _jsonSerializer;
        }
    }
}
