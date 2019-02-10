using System;
using Xunit;

namespace JWT.Tests.Common
{
    public class JwtValidatorTest
    {
        /*
           payloadJson))
              return new ArgumentException(nameof(payloadJson));

          if (String.IsNullOrWhiteSpace(decodedCrypto))
              return new ArgumentException(nameof(decodedCrypto));

          if (String.IsNullOrWhiteSpace(decodedSignature))
              return new ArgumentException(nameof(decodedSignature));
           */

        [Theory]
        [InlineData(null, null, null)]
        public void Validate_Should_Throw_Exception_Argument_Is_Null_Or_Empty(string payloadJson, string decodedCrypto, string decodedSignature)
        {
            Assert.Throws<ArgumentException>(() => new JwtValidator(null, null).Validate(payloadJson, decodedCrypto, decodedSignature));
        }

        [Fact]
        public void Validate_Should_Throw_Exception_PayloadJson_Is_Empty()
        {
            string payloadJson = "";
            string decodedCrypto = null;
            string decodedSignature = null;

            Assert.Throws<ArgumentException>(() => new JwtValidator(null, null).Validate(payloadJson, decodedCrypto, decodedSignature));
        }
    }
}