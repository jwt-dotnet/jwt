namespace JWT.Serializers
{
    public interface IJsonSerializerFactory
    {
        IJsonSerializer CreateSerializer();
    }
}
