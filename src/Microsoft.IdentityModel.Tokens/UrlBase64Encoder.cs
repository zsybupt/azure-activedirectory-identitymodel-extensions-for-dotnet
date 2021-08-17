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
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Base64 encoder for Url
    /// </summary>
    public class UrlBase64Encoder
    {
        /// <summary>
        /// Char 62
        /// </summary>
        private const char Base64UrlCharacter62 = '-';

        /// <summary>
        /// Char 63
        /// </summary>
        private const char Base64UrlCharacter63 = '_';

        /// <summary>
        /// Encoding table
        /// </summary>
        internal static readonly char[] s_base64Table =
        {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9',
            Base64UrlCharacter62,
            Base64UrlCharacter63
        };

        /// <summary>
        /// Reused encoder.
        /// </summary>
        private static UrlBase64Encoder reusedEncoder;

        /// <summary>
        /// Char buffer
        /// </summary>
        private char[] _charBuffer = new char[128];

        /// <summary>
        /// Char count in the buffer
        /// </summary>
        private int _charLength;

        /// <summary>
        /// Byte buffer
        /// </summary>
        private byte[] _byteBuffer;

        /// <summary>
        /// Gets char count.
        /// </summary>
        public int Length => _charLength;

        /// <summary>
        /// Acquire encoder.
        /// </summary>
        /// <returns>Empty encoder.</returns>
        public static UrlBase64Encoder AcquireEncoder()
        {
            var encoder = Interlocked.Exchange(ref UrlBase64Encoder.reusedEncoder, null);

            if (encoder == null)
            {
                encoder = new UrlBase64Encoder();
            }

            return encoder;
        }

        /// <summary>
        /// Release encoder for reuse.
        /// </summary>
        public void Release()
        {
            Clear();

            UrlBase64Encoder.reusedEncoder = this;
        }

        /// <summary>
        /// Clear for reuse
        /// </summary>
        public void Clear()
        {
            _charLength = 0;
        }

        /// <summary>
        /// Append a single char without encoding.
        /// </summary>
        /// <param name="ch">Char to append</param>
        public void Append(char ch)
        {
            EnsureSpace(1);

            _charBuffer[_charLength++] = ch;
        }

        /// <summary>
        /// Encode a string
        /// </summary>
        /// <param name="str">string to encode</param>
        public void Encode(string str)
        {
            if (str == null)
            {
                throw new ArgumentNullException(nameof(str));
            }

            int length = str.Length;

            if (length != 0)
            {
                bool ascii = true;

                foreach (char ch in str)
                {
                    if (ch >= 128)
                    {
                        ascii = false;
                        break;
                    }
                }

                if (ascii)
                {
                    EncodeAscii(str, 0, length);
                }
                else
                {
                    // Worst case encoded length.
                    int byteLength = length * 6;

                    if ((_byteBuffer == null) || (_byteBuffer.Length < byteLength))
                    {
                        _byteBuffer = new byte[byteLength];
                    }

                    byteLength = Encoding.UTF8.GetBytes(str, 0, length, _byteBuffer, 0);

                    Encode(_byteBuffer, 0, byteLength);
                }
            }
        }

        /// <summary>
        /// Encoding ASCII string.
        /// </summary>
        /// <param name="data">String data</param>
        /// <param name="offset">start position</param>
        /// <param name="length">data length</param>
        public void EncodeAscii(string data, int offset, int length)
        {
            if (data == null)
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(data)));

            EnsureSpace((length + 2) / 3 * 4);

            int i;

            char[] table = UrlBase64Encoder.s_base64Table;
            char[] output = _charBuffer;

            int j = _charLength;

            int lengthmod3 = length % 3;
            int limit = offset + (length - lengthmod3);

            for (i = offset; i < limit; i += 3)
            {
                char d0 = data[i];
                char d1 = data[i + 1];
                char d2 = data[i + 2];

                output[j + 0] = table[(d0 & 0xfc) >> 2];
                output[j + 1] = table[((d0 & 0x03) << 4) | ((d1 & 0xf0) >> 4)];
                output[j + 2] = table[((d1 & 0x0f) << 2) | ((d2 & 0xc0) >> 6)];
                output[j + 3] = table[d2 & 0x3f];
                j += 4;
            }

            //Where we left off before
            i = limit;

            switch (lengthmod3)
            {
                case 2:
                    {
                        char d0 = data[i];
                        char d1 = data[i + 1];

                        output[j + 0] = table[(d0 & 0xfc) >> 2];
                        output[j + 1] = table[((d0 & 0x03) << 4) | ((d1 & 0xf0) >> 4)];
                        output[j + 2] = table[(d1 & 0x0f) << 2];
                        j += 3;
                    }
                    break;

                case 1:
                    {
                        char d0 = data[i];

                        output[j + 0] = table[d0 >> 2];
                        output[j + 1] = table[(d0 & 0x03) << 4];
                        j += 2;
                    }
                    break;
            }

            _charLength = j;
        }

        /// <summary>
        /// Encoding from byte array.
        /// </summary>
        /// <param name="data">Data array</param>
        /// <param name="offset">start position</param>
        /// <param name="length">data length</param>
        public void Encode(byte[] data, int offset, int length)
        {
            if (data == null)
                throw LogHelper.LogArgumentNullException("data");

            EnsureSpace((length + 2) / 3 * 4);

            int i;

            char[] table = UrlBase64Encoder.s_base64Table;
            char[] output = _charBuffer;

            int j = _charLength;

            int lengthmod3 = length % 3;
            int limit = offset + (length - lengthmod3);

            for (i = offset; i < limit; i += 3)
            {
                byte d0 = data[i];
                byte d1 = data[i + 1];
                byte d2 = data[i + 2];

                output[j + 0] = table[(d0 & 0xfc) >> 2];
                output[j + 1] = table[((d0 & 0x03) << 4) | ((d1 & 0xf0) >> 4)];
                output[j + 2] = table[((d1 & 0x0f) << 2) | ((d2 & 0xc0) >> 6)];
                output[j + 3] = table[d2 & 0x3f];
                j += 4;
            }

            //Where we left off before
            i = limit;

            switch (lengthmod3)
            {
                case 2:
                    {
                        byte d0 = data[i];
                        byte d1 = data[i + 1];

                        output[j + 0] = table[(d0 & 0xfc) >> 2];
                        output[j + 1] = table[((d0 & 0x03) << 4) | ((d1 & 0xf0) >> 4)];
                        output[j + 2] = table[(d1 & 0x0f) << 2];
                        j += 3;
                    }
                    break;

                case 1:
                    {
                        byte d0 = data[i];

                        output[j + 0] = table[d0 >> 2];
                        output[j + 1] = table[(d0 & 0x03) << 4];
                        j += 2;
                    }
                    break;
            }

            _charLength = j;
        }

        /// <summary>
        /// Convert content to byte array.
        /// </summary>
        /// <param name="encoding">Encoding to use.</param>
        /// <returns>encoded data.</returns>
        public byte[] GetBytes(Encoding encoding)
        {
            if (encoding == null)
            {
                throw new ArgumentNullException(nameof(encoding));
            }

            int length = encoding.GetByteCount(_charBuffer, 0, _charLength);

            byte[] result = new byte[length];

            encoding.GetBytes(_charBuffer, 0, _charLength, result, 0);

            return result;
        }

        /// <summary>
        /// Convert content to string.
        /// </summary>
        /// <returns>String content.</returns>
        public override string ToString()
        {
            return new string(_charBuffer, 0, _charLength);
        }

        /// <summary>
        /// Ensure char buffer has enough space.
        /// </summary>
        /// <param name="toAdd">Char to be added.</param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void EnsureSpace(int toAdd)
        {
            int total = _charLength + toAdd;

            if (_charBuffer.Length < total)
            {
                Array.Resize(ref _charBuffer, Math.Max(total, _charBuffer.Length * 2));
            }
        }
    }

}
