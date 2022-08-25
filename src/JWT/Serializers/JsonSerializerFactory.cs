namespace JWT.Serializers
{
    public static class JsonSerializerFactory
    {
        private static IJsonSerializer _serializer;

        public static IJsonSerializer Serializer
        {
            get
            {
#if MODERN_DOTNET
                return _serializer ??= new SystemTextSerializer();
#else
                
                return _serializer ??= new JsonNetSerializer();
#endif
            }
#if MODERN_DOTNET
            set
            {
                _serializer = value;
            }
#endif
        }

        public static IJsonSerializer CreateSerializer() => Serializer;
    }
}