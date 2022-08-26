using System;
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
                    Assert.AreEqual(nameof(SystemTextSerializer), defaultSerializerClass);
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
            string version = Assembly.GetEntryAssembly()?.GetCustomAttribute<TargetFrameworkAttribute>()?.FrameworkName;

            if (!string.IsNullOrEmpty(version))
            {
                return version;
            }
            
            version = AppDomain.CurrentDomain.SetupInformation.TargetFrameworkName;
            return version;
        }
    }
}