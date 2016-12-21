using Newtonsoft.Json;

#if !NETCOREAPP1_0
using JsonSerializer = ServiceStack.Text.JsonSerializer;
#endif

namespace JWT.Tests
{

#if !NETCOREAPP1_0
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
#endif

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
