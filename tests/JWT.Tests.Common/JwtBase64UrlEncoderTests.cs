using System;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace JWT.Tests
{
    [TestClass]
    public class JwtBase64UrlEncoderTests
    {
        private static readonly JwtBase64UrlEncoder _encoder = new JwtBase64UrlEncoder();

        [TestMethod]
        public void Encode_And_Decode_Should_Match_Reference_Implementation_For_Random_Inputs()
        {
            var random = new Random(20261119);

            for (var length = 1; length <= 1100; length++)
            {
                var input = new byte[length];
                random.NextBytes(input);

                var expected = ReferenceEncode(input);

                var encoded = _encoder.Encode(input);
                encoded.Should().Be(expected, "encoding {0} bytes", length);

                var decoded = _encoder.Decode(encoded);
                decoded.Should().Equal(input, "decoding {0} bytes", length);
            }
        }

        [TestMethod]
        [DataRow(1, "_w")]
        [DataRow(2, "__8")]
        [DataRow(3, "____")]
        [DataRow(4, "_____w")]
        [DataRow(5, "______8")]
        [DataRow(6, "________")]
        public void Encode_Should_Omit_Padding(int length, string expected)
        {
            var input = new byte[length];
            for (var i = 0; i < length; i++)
                input[i] = 0xFF;

            var encoded = _encoder.Encode(input);

            encoded.Should().Be(expected);
            _encoder.Decode(encoded).Should().Equal(input);
        }

        [TestMethod]
        [DataRow("AA==", "AA==")]
        [DataRow("AAA=", "AAA=")]
        [DataRow("AA", "AA==")]
        [DataRow("AAA", "AAA=")]
        [DataRow("AAAA", "AAAA")]
        public void Decode_Should_Accept_Padded_And_Unpadded_Input(string input, string expectedBase64)
        {
            var decoded = _encoder.Decode(input);

            decoded.Should().Equal(Convert.FromBase64String(expectedBase64));
        }

        [TestMethod]
        [DataRow("AA A")]
        [DataRow(" AAAA")]
        [DataRow("AAAA\n")]
        [DataRow("AA\r\nAA")]
        [DataRow("AA\tA")]
        public void Decode_Should_Throw_On_Whitespace(string input)
        {
            Action action = () => _encoder.Decode(input);

            action.Should().Throw<FormatException>();
        }

        [TestMethod]
        [DataRow("A")]
        [DataRow("AAAAA")]
        [DataRow("AAAA=")]
        [DataRow("AAAA==")]
        public void Decode_Should_Throw_On_Invalid_Length(string input)
        {
            Action action = () => _encoder.Decode(input);

            action.Should().Throw<FormatException>();
        }

        [TestMethod]
        [DataRow("Pz8+")]
        [DataRow("Pz8/")]
        public void Decode_Should_Handle_Standard_Base64_Characters_Depending_On_Target(string input)
        {
            Action action = () => _encoder.Decode(input);

#if NET8_0_OR_GREATER
            action.Should().Throw<FormatException>();
#else
            action.Should().NotThrow();
            _encoder.Decode(input).Should().Equal(Convert.FromBase64String(input));
#endif
        }

        [TestMethod]
        [DataRow("AB", "AA==")]
        [DataRow("AAB", "AAA=")]
        public void Decode_Should_Handle_Non_Canonical_Trailing_Bits_Depending_On_Target(string input, string expectedBase64)
        {
            Action action = () => _encoder.Decode(input);

#if NET8_0_OR_GREATER
            action.Should().Throw<FormatException>();
#else
            action.Should().NotThrow();
            _encoder.Decode(input).Should().Equal(Convert.FromBase64String(expectedBase64));
#endif
        }

        [TestMethod]
        public void Encode_Should_Throw_On_Null_Input()
        {
            Action action = () => _encoder.Encode(null);

            action.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void Encode_Should_Throw_On_Empty_Input()
        {
            Action action = () => _encoder.Encode(new byte[0]);

            action.Should().ThrowExactly<ArgumentOutOfRangeException>();
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow(" ")]
        public void Decode_Should_Throw_On_Null_Or_Whitespace_Input(string input)
        {
            Action action = () => _encoder.Decode(input);

            action.Should().ThrowExactly<ArgumentException>();
        }

        private static string ReferenceEncode(byte[] input) =>
            Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
