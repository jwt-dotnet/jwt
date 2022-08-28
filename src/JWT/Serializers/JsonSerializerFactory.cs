namespace JWT.Serializers
{
    public class JsonSerializerFactory
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

        public JsonSerializerFactory(IJsonSerializer jsonSerializer)
        {
            _jsonSerializer = jsonSerializer;
        }

        public IJsonSerializer CreateSerializer()
        {
            return _jsonSerializer;
        }
    }
}