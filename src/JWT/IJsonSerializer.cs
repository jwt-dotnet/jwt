using System;

namespace JWT
{
    /// <summary>
    /// Provides JSON Serialize and Deserialize. Allows custom serializers used.
    /// </summary>
    public interface IJsonSerializer
    {
        /// <summary>
        /// Serializes an object to a JSON string.
        /// </summary>
        /// <param name="obj">The object to serialize.</param>
        /// <returns>JSON string</returns>
        string Serialize(object obj);

        /// <summary>
        /// Deserializes a JSON string to an object of specified type.
        /// </summary>
        /// <param name="type">The type of the object to deserialize to.</param>
        /// <param name="json">The JSON string deserialize.</param>
        /// <returns>Strongly-typed object.</returns>
        object Deserialize(Type type, string json);
    }

    /// <summary>
    /// Extension methods for <seealso cref="IJsonSerializer" />
    ///</summary>
    public static class JsonSerializerExtensions
    {
        /// <summary>
        /// Deserializes a JSON string to an object of specified type.
        /// </summary>
        /// <typeparam name="T">The type of the object to deserialize to.</typeparam>
        /// <param name="jsonSerializer">The JSON serializer instance.</param>
        /// <param name="json">JSON string</param>
        /// <returns>Strongly-typed object.</returns>
        public static T Deserialize<T>(this IJsonSerializer jsonSerializer, string json) =>
            (T)jsonSerializer.Deserialize(typeof(T), json);
    }
}