using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT.Serializers
{
    public class JsonNetSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JObject.FromObject(obj).ToString(Formatting.None);
        }

        public T Deserialize<T>(string json)
        {
            return JObject.Parse(json).ToObject<T>();
        }
    }
}