using System;
using FluentAssertions;
using JWT.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace JWT.Tests.Algorithms
{
    [TestClass]
    public class DelegateAlgorithmFactoryTests
    {
        [TestMethod]
        public void Ctor_Accepting_Func_IJwtAlgorithm_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateAlgorithmFactory((Func<IJwtAlgorithm>)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Accepting_Func_JwtDecoderContext_IJwtAlgorithm_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateAlgorithmFactory((Func<JwtDecoderContext, IJwtAlgorithm>)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Accepting_IAlgorithmFactory_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateAlgorithmFactory((IAlgorithmFactory)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Ctor_Accepting_IAlgorithm_Should_Throw_When_Param_Is_Null()
        {
            Action action = () => new DelegateAlgorithmFactory((IJwtAlgorithm)null);

            action.Should()
                  .Throw<ArgumentNullException>();
        }

        [TestMethod]
        public void Create_Should_Return_Algorithm_Returned_By_Inner_Factory()
        {
            var expected = Mock.Of<IJwtAlgorithm>();

            var context = new JwtDecoderContext();
            var innerFactory = new Mock<IAlgorithmFactory>();
            innerFactory.Setup(f => f.Create(context)).Returns(expected);

            var delFactory = new DelegateAlgorithmFactory(innerFactory.Object);
            var actual = delFactory.Create(context);

            actual.Should().Be(expected);

            innerFactory.VerifyAll();
        }
    }
}