using Newtonsoft.Json.Linq;

namespace JWT
{
    public class JsonNetSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            return JObject.FromObject(obj).ToString();
        }

        public T Deserialize<T>(string json)
        {
            return JObject.Parse(json).ToObject<T>();
        }
    }
}