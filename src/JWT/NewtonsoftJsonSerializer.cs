#if NETSTANDARD1_6

namespace JWT
{
    using Newtonsoft.Json;

    public class NewtonsoftJsonSerializer : IJsonSerializer
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
#endif
