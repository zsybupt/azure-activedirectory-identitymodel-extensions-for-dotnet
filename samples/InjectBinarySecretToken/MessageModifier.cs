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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Channels;
using System.Xml;

namespace InjectBinarySecretToken
{
    public class MessageModifier
    {
        X509Certificate2 _certToInsert;
        public MessageModifier(X509Certificate2 certToInsert)
        {
            _certToInsert = certToInsert;
        }

        /// <summary>
        /// Add BinarySecurityToken after Timestamp.
        /// </summary>
        /// <param name="message"></param>
        public virtual void OnReceive(ref Message message)
        {
            var messageStream = new MemoryStream();
            message.CreateBufferedCopy(Int32.MaxValue).WriteMessage(messageStream);
            messageStream.Position = 0;

            var writerStream = new MemoryStream();
            var xmlReader = XmlDictionaryReader.CreateDictionaryReader(XmlDictionaryReader.Create(messageStream));
            var xmlWriter = XmlDictionaryWriter.CreateDictionaryWriter(XmlDictionaryWriter.Create(writerStream));
            var id = Guid.NewGuid().ToString();
            string securityNamespace = null;
            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement() && xmlReader.LocalName.Equals("Security"))
                { 
                    securityNamespace = xmlReader.NamespaceURI;
                }

                // TODO - We will have to make sure that 
                if (xmlReader.NodeType.Equals(XmlNodeType.EndElement))
                {
                    if (xmlReader.LocalName.Equals("Timestamp", StringComparison.OrdinalIgnoreCase))
                    {
                        RecordNode(xmlReader, xmlWriter);
                        var x509Data = Convert.ToBase64String(_certToInsert.GetRawCertData());
                        xmlWriter.WriteStartElement("BinarySecurityToken", securityNamespace);
                        xmlWriter.WriteAttributeString("Id", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", id);
                        xmlWriter.WriteAttributeString("ValueType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
                        xmlWriter.WriteAttributeString("EncodingType", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                        xmlWriter.WriteString(x509Data);
                        xmlWriter.WriteEndElement();
                    }
                    else
                    {
                        RecordNode(xmlReader, xmlWriter);
                    }
                }
                else
                {
                    RecordNode(xmlReader, xmlWriter);
                }
            }

            xmlWriter.Flush();
            writerStream.Position = 0;
            var modifiedMessage = Message.CreateMessage(XmlReader.Create(writerStream), 2147483647, message.Version);
            var modifiedBuffer = modifiedMessage.CreateBufferedCopy(Int32.MaxValue);
            message = modifiedBuffer.CreateMessage();
        }

        /// <summary>
        /// Writes the current node into the writer
        /// </summary>
        /// <param name="reader"></param>
        /// <param name="writer"></param>
        private static void RecordNode(XmlReader reader, XmlWriter writer)
        {
            switch (reader.NodeType)
            {
                case XmlNodeType.CDATA:
                    writer.WriteCData(reader.Value);
                    break;
                case XmlNodeType.Comment:
                    writer.WriteComment(reader.Value);
                    break;

                case XmlNodeType.DocumentType:
                    writer.WriteDocType(reader.Name, reader.GetAttribute("PUBLIC"), reader.GetAttribute("SYSTEM"), reader.Value);
                    break;

                case XmlNodeType.Element:
                    writer.WriteStartElement(reader.Prefix, reader.LocalName, reader.NamespaceURI);
                    writer.WriteAttributes(reader, true);
                    if (reader.IsEmptyElement)
                        writer.WriteEndElement();
                    break;

                case XmlNodeType.EndElement:
                    writer.WriteFullEndElement();
                    break;

                case XmlNodeType.Text:
                    writer.WriteString(reader.Value);
                    break;

                case XmlNodeType.Whitespace:
                case XmlNodeType.SignificantWhitespace:
                    writer.WriteWhitespace(reader.Value);
                    break;

                case XmlNodeType.EntityReference:
                    writer.WriteEntityRef(reader.Name);
                    break;

                case XmlNodeType.XmlDeclaration:
                case XmlNodeType.ProcessingInstruction:
                    writer.WriteProcessingInstruction(reader.Name, reader.Value);
                    break;
            }
        }
    }
}
