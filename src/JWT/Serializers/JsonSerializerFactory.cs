namespace JWT.Serializers
{
    public static class JsonSerializerFactory
    {
        private static IJsonSerializer _jsonSerializer;

#if MODERN_DOTNET
        public static void SetSerializer(IJsonSerializer jsonSerializer)
        {
            _jsonSerializer = jsonSerializer;
        }
#endif

        public static IJsonSerializer CreateSerializer()
        {
#if MODERN_DOTNET
            return _jsonSerializer ??= new SystemTextSerializer();
#else
            return _jsonSerializer ??= new JsonNetSerializer();
#endif
        }
    }
}