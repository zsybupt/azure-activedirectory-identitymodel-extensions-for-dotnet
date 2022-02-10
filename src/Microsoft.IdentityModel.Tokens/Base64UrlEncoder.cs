//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Encodes and Decodes strings as Base64Url encoding.
    /// </summary>
    public static class Base64UrlEncoder
    {
        private const char base64PadCharacter = '=';
#if NET45
       // private const string doubleBase64PadCharacter = "==";
#endif
        //private const char base64Character62 = '+';
        //private const char base64Character63 = '/';
        private const char base64UrlCharacter62 = '-';
        private const char base64UrlCharacter63 = '_';

        /// <summary>
        /// Encoding table
        /// </summary>
        internal static readonly char[] s_base64Table =
        {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9',
            base64UrlCharacter62,
            base64UrlCharacter63
        };

        private static readonly sbyte[] s_base64UrlDecodeTable = // rely on C# compiler optimization to reference static data
        {
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,         // 62 is placed at index 43 (for +), 63 at index 47 (for /)
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,         // 52-61 are placed at index 48-57 (for 0-9), 64 at index 61 (for =)
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,         // 0-25 are placed at index 65-90 (for A-Z)
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,         // 26-51 are placed at index 97-122 (for a-z)
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // Bytes over 122 ('z') are invalid and cannot be decoded
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,         // Hence, padding the map with 255, which indicates invalid input
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        };

        /// <summary>
        /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
        /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
        /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
        /// The changes make the encoding alphabet file and URL safe.
        /// </summary>
        /// <param name="arg">string to encode.</param>
        /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
        public static string Encode(string arg)
        {
            _ = arg ?? throw LogHelper.LogArgumentNullException(nameof(arg));

            return Encode(Encoding.UTF8.GetBytes(arg));
        }

        /// <summary>
        /// Converts a subset of an array of 8-bit unsigned integers to its equivalent string representation which is encoded with base-64-url digits. Parameters specify
        /// the subset as an offset in the input array, and the number of elements in the array to convert.
        /// </summary>
        /// <param name="inArray">An array of 8-bit unsigned integers.</param>
        /// <param name="length">An offset in inArray.</param>
        /// <param name="offset">The number of elements of inArray to convert.</param>
        /// <returns>The string representation in base 64 url encoding of length elements of inArray, starting at position offset.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is negative OR offset plus length is greater than the length of inArray.</exception>
        public static string Encode(byte[] inArray, int offset, int length)
        {
            _ = inArray ?? throw LogHelper.LogArgumentNullException(nameof(inArray));

            if (length == 0)
                return string.Empty;

            if (length < 0)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(LogHelper.FormatInvariant(LogMessages.IDX10106, LogHelper.MarkAsNonPII(nameof(length)), LogHelper.MarkAsNonPII(length))));

            if (offset < 0 || inArray.Length < offset)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(LogHelper.FormatInvariant(LogMessages.IDX10106, LogHelper.MarkAsNonPII(nameof(offset)), LogHelper.MarkAsNonPII(offset))));

            if (inArray.Length < offset + length)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(LogHelper.FormatInvariant(LogMessages.IDX10106, LogHelper.MarkAsNonPII(nameof(length)), LogHelper.MarkAsNonPII(length))));

            int lengthmod3 = length % 3;
            int limit = offset + (length - lengthmod3);
            char[] output = new char[(length + 2) / 3 * 4];
            char[] table = s_base64Table;
            int i, j = 0;

            // takes 3 bytes from inArray and insert 4 bytes into output
            for (i = offset; i < limit; i += 3)
            {
                byte d0 = inArray[i];
                byte d1 = inArray[i + 1];
                byte d2 = inArray[i + 2];

                output[j + 0] = table[d0 >> 2];
                output[j + 1] = table[((d0 & 0x03) << 4) | (d1 >> 4)];
                output[j + 2] = table[((d1 & 0x0f) << 2) | (d2 >> 6)];
                output[j + 3] = table[d2 & 0x3f];
                j += 4;
            }

            //Where we left off before
            i = limit;

            switch (lengthmod3)
            {
                case 2:
                    {
                        byte d0 = inArray[i];
                        byte d1 = inArray[i + 1];

                        output[j + 0] = table[d0 >> 2];
                        output[j + 1] = table[((d0 & 0x03) << 4) | (d1 >> 4)];
                        output[j + 2] = table[(d1 & 0x0f) << 2];
                        j += 3;
                    }
                    break;

                case 1:
                    {
                        byte d0 = inArray[i];

                        output[j + 0] = table[d0 >> 2];
                        output[j + 1] = table[(d0 & 0x03) << 4];
                        j += 2;
                    }
                    break;

                //default or case 0: no further operations are needed.
            }

            return new string(output, 0, j);
        }

        /// <summary>
        /// Converts a subset of an array of 8-bit unsigned integers to its equivalent string representation which is encoded with base-64-url digits.
        /// </summary>
        /// <param name="inArray">An array of 8-bit unsigned integers.</param>
        /// <returns>The string representation in base 64 url encoding of length elements of inArray, starting at position offset.</returns>
        /// <exception cref="ArgumentNullException">'inArray' is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">offset or length is negative OR offset plus length is greater than the length of inArray.</exception>
        public static string Encode(byte[] inArray)
        {
            _ = inArray ?? throw LogHelper.LogArgumentNullException(nameof(inArray));

            return Encode(inArray, 0, inArray.Length);
        }

        internal static string EncodeString(string str)
        {
            _ = str ?? throw LogHelper.LogArgumentNullException(nameof(str));

            return Encode(Encoding.UTF8.GetBytes(str));
        }

        /// <summary>
        ///  Converts the specified string, which encodes binary data as base-64-url digits, to an equivalent 8-bit unsigned integer array.</summary>
        /// <param name="str">base64Url encoded string.</param>
        /// <returns>UTF8 bytes.</returns>
        public static byte[] DecodeBytes(string str)
        {
            _ = str ?? throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, str)));

            int length = GetStringEnd(str);
            int mod = length % 4;
            if (mod == 1)// mod can only be 0, 2 or 3 after encoding.
            {
                throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
            }
            int left = mod == 0 ? 0 : mod - 1;
            int limit = length - mod;
            int resultLength = length / 4 * 3 + left;
            byte[] result = new byte[resultLength];
            int encodedIndex = 0;
            int decodedIndex = 0;
            for (; encodedIndex < limit; encodedIndex += 4)
            {
                int i0 = str[encodedIndex];
                int i1 = str[encodedIndex + 1];
                int i2 = str[encodedIndex + 2];
                int i3 = str[encodedIndex + 3];

                if (((i0 | i1 | i2 | i3) & 0xffffff00) != 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }
                i0 = s_base64UrlDecodeTable[i0];
                i1 = s_base64UrlDecodeTable[i1];
                i2 = s_base64UrlDecodeTable[i2];
                i3 = s_base64UrlDecodeTable[i3];

                i0 <<= 18;
                i1 <<= 12;
                i2 <<= 6;

                i0 |= i3;
                i1 |= i2;
                i0 |= i1;

                if (i0 < 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }

                result[decodedIndex] = (byte)(i0 >> 16);
                result[decodedIndex + 1] = (byte)(i0 >> 8);
                result[decodedIndex + 2] = (byte)i0;

                decodedIndex += 3;
            }

            encodedIndex = limit;

            if (mod == 2)
            {
                int i0 = str[encodedIndex];
                int i1 = str[encodedIndex + 1];
                if (((i0 | i1) & 0xffffff00) != 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }
                i0 = s_base64UrlDecodeTable[i0];
                i1 = s_base64UrlDecodeTable[i1];

                i0 <<= 2;
                i1 >>= 4;
                i0 = i0 | i1;
                if (i0 < 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }

                result[decodedIndex] = (byte)i0;
            }
            else if (mod == 3)
            {
                int i0 = str[encodedIndex];
                int i1 = str[encodedIndex + 1];
                int i2 = str[encodedIndex + 2];

                if (((i0 | i1) & 0xffffff00) != 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }

                i0 = s_base64UrlDecodeTable[i0];
                i1 = s_base64UrlDecodeTable[i1];
                i2 = s_base64UrlDecodeTable[i2];

                i0 <<= 12;
                i1 <<= 6;
                i1 |= i2;
                i0 |= i1;

                if (i0 < 0)
                {
                    throw LogHelper.LogExceptionMessage(new FormatException("bad format base64urlencoded string"));
                }

                result[decodedIndex] = (byte)(i0 >> 10);
                decodedIndex++;
                result[decodedIndex] = (byte)(i0 >> 2);
            }

            return result;
        }

        /// <summary>
        /// Decodes the string from Base64UrlEncoded to UTF8.
        /// </summary>
        /// <param name="arg">string to decode.</param>
        /// <returns>UTF8 string.</returns>
        public static string Decode(string arg)
        {
            return Encoding.UTF8.GetString(DecodeBytes(arg));
        }

        private static int GetStringEnd(string str)
        {
            int length = str.Length;
            if (length == 0)
            {
                return 0;
            }
            if (str[length - 1] != base64PadCharacter)
            {
                return length;
            }

            if (length % 4 != 0) // invalid base64 string
            {
                throw new ArgumentException($"{str} is not a valid base64 or base64url string");
            }

            if (str[length - 2] == base64PadCharacter)
            {
                return length - 2;
            }

            return length - 1;
        }
    }
}
