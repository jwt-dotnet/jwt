using System.Web.Script.Serialization;

namespace JWT.Tests.Serializers
{
    public class WebScriptJsonSerializer : IJsonSerializer
    {
        public string Serialize(object obj)
        {
            var serializer = new JavaScriptSerializer();
            return serializer.Serialize(obj);
        }

        public T Deserialize<T>(string json)
        {
            var serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>(json);
        }
    }
}