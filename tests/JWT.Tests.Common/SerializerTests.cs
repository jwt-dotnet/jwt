using System;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class SerializerTests
    {
        [TestMethod]
        public void Serializer_Should_Use_Correct_Default()
        {
            var serializer = JsonSerializerFactory.Serializer;
            Console.WriteLine(serializer.GetType().Name);
        }
    }
}