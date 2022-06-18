namespace JWT.Serializers
{
    internal static class JsonSerializerFactory
    {
        public static IJsonSerializer CreateSerializer()
        {
#if SYSTEM_TEXT_JSON
            return new SystemTextSerializer();
#elif NEWTONSOFT_JSON
            return new JsonNetSerializer();
#else
            throw new System.NotSupportedException();
#endif
        }
    }
}