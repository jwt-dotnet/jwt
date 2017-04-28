using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace JWT.Serializers
{
    /// <summary>
    /// JSON serializer using Newtonsoft.Json implementation.
    /// </summary>
    public sealed class JsonNetSerializer : IJsonSerializer
    {
        /// <summary>
        /// Serialize the given object.
        /// </summary>
        /// <param name="obj">The object to serialize.</param>
        /// <returns></returns>
        public string Serialize(object obj)
        {
            return JObject.FromObject(obj).ToString(Formatting.None);
        }

        /// <summary>
        /// Deserialize the given string.
        /// </summary>
        /// <typeparam name="T">The type to deserialize the string to.</typeparam>
        /// <param name="json">The JSON to be deserialized.</param>
        /// <returns></returns>
        public T Deserialize<T>(string json)
        {
            return JObject.Parse(json).ToObject<T>();
        }
    }
}