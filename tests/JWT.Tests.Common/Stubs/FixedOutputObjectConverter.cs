using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JWT.Tests.Stubs
{
    public sealed class FixedOutputObjectConverter : JsonConverter<object>
    {
        public override object Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
            throw new NotSupportedException();

        public override void Write(Utf8JsonWriter writer, object value, JsonSerializerOptions options) =>
            writer.WriteStringValue("fixed");
    }
}
