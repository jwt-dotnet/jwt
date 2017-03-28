using ServiceStack.Text;

namespace JWT.Tests.NETFramework.Serializers
{
    public class ServiceStackJsonSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JsonSerializer.SerializeToString(obj);
        }

        public T Deserialize<T>(string json)
        {
            return JsonSerializer.DeserializeFromString<T>(json);
        }
    }
}