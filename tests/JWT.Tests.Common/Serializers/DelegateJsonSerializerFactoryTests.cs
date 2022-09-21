using System;
using FluentAssertions;
using JWT.Serializers;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class DelegateJsonSerializerFactoryTests
    {
        [TestMethod]
        public void Ctor_Accepting_JsonSerializer_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateJsonSerializerFactory((IJsonSerializer)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Accepting_Factory_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateJsonSerializerFactory((IJsonSerializerFactory)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Accepting_Func_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateJsonSerializerFactory((Func<IJsonSerializer>)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Create_Should_Return_JsonSerializer_Returned_By_Inner_Factory()
        {
            var expected = Mock.Of<IJsonSerializer>();

            var delFactory = new DelegateJsonSerializerFactory(() => expected);
            var actual = delFactory.Create();

            actual.Should().Be(expected);
        }
    }
}