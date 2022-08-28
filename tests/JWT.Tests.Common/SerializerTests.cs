using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Versioning;
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
            var serializer = new JsonSerializerFactory().CreateSerializer();

            var dotnetVersion = GetRunningDotnetVersion();
            Console.WriteLine($"Dotnet version: {dotnetVersion}");

            var defaultSerializerClass = serializer.GetType().Name;
            Console.WriteLine($"Default serializer class: {defaultSerializerClass}");

            if (dotnetVersion is ".NETFramework,Version=v4.6.2" ||
                dotnetVersion.StartsWith(".NETCoreApp"))
            {
                Assert.AreEqual("SystemTextSerializer", defaultSerializerClass);
            }
            else if (dotnetVersion == ".NETFramework,Version=v4.6.1")
            {
                Assert.AreEqual("JsonNetSerializer", defaultSerializerClass);
            }
            else
            {
                Assert.Fail($"Unrecognized dotnet version {dotnetVersion}");
            }
        }

        /// <summary>
        /// Copied from: https://stackoverflow.com/a/49754978
        /// </summary>
        /// <returns>The running dotnet version.</returns>
        private string GetRunningDotnetVersion()
        {
            var version = Assembly.GetExecutingAssembly()
                .GetCustomAttributes(typeof(TargetFrameworkAttribute), false)
                .Cast<TargetFrameworkAttribute>()
                .Single()
                .FrameworkName;
            return version;
        }
    }
}