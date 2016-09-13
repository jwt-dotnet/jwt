using Newtonsoft.Json;
using JsonSerializer = ServiceStack.Text.JsonSerializer;

namespace JWT.Tests
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

    public class NewtonJsonSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JsonConvert.SerializeObject(obj);
        }

        public T Deserialize<T>(string json)
        {
            return JsonConvert.DeserializeObject<T>(json);
        }
    }
}