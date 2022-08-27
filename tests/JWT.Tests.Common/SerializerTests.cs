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
            var serializer = JsonSerializerFactory.CreateSerializer();

            var dotnetVersion = GetRunningDotnetVersion();
            Console.WriteLine($"Dotnet version: {dotnetVersion}");

            var defaultSerializerClass = serializer.GetType().Name;
            Console.WriteLine($"Default serializer class: {defaultSerializerClass}");

            switch (dotnetVersion)
            {
                case ".NETFramework,Version=v4.6.2":
                case ".NETCoreApp,Version=v3.0":
                case ".NETCoreApp,Version=v6.0":
                    Assert.AreEqual("SystemTextSerializer", defaultSerializerClass);
                    break;
                    
                case ".NETFramework,Version=v4.6.1":
                    Assert.AreEqual("JsonNetSerializer", defaultSerializerClass);
                    break;
                default:
                    Assert.Fail($"Unrecognized dotnet version {dotnetVersion}");
                    break;
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