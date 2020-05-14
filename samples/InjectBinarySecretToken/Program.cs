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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;

// if certs are expired, create new ones using Powershell in administrator mode
// New-SelfSignedCertificate -Subject "CN=Client" -CertStoreLocation Cert:\LocalMachine\My -FriendlyName "Client" -KeyUsageProperty All -KeyExportPolicy Exportable  -Keyspec Signature -Provider "Microsoft Strong Cryptographic Provider"
// New-SelfSignedCertificate -Subject "CN=Service" -CertStoreLocation Cert:\LocalMachine\My -FriendlyName "Service" -KeyUsageProperty All -KeyExportPolicy Exportable  -Keyspec Signature -Provider "Microsoft Strong Cryptographic Provider"
// New-SelfSignedCertificate -Subject "CN=Injected" -CertStoreLocation Cert:\LocalMachine\My -FriendlyName "Injected" -KeyUsageProperty All -KeyExportPolicy Exportable  -Keyspec Signature -Provider "Microsoft Strong Cryptographic Provider"

namespace InjectBinarySecretToken
{
    class Program
    {
        static void Main(string[] args)
        {
            var clientCert = new X509Certificate2("Client.pfx", "Client", X509KeyStorageFlags.EphemeralKeySet);
            var injectedCert = new X509Certificate2("Injected.pfx", "Injected", X509KeyStorageFlags.EphemeralKeySet);
            var serviceCert = new X509Certificate2("Service.pfx", "Service", X509KeyStorageFlags.EphemeralKeySet);
            var baseAddress = "http://127.0.0.1:8080/InjectBinarySecretToken";
            var serviceBinding = GetServiceBinding();

            var serviceHost = new ServiceHost(typeof(RequestReply), new Uri(baseAddress));
            serviceHost.AddServiceEndpoint(typeof(IRequestReply), serviceBinding, baseAddress);
            serviceHost.Credentials.ServiceCertificate.Certificate = serviceCert;
            serviceHost.Credentials.ClientCertificate.Certificate = clientCert;
            serviceHost.Credentials.ClientCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            serviceHost.Open();

            // Need a custom endpoint identity so that WCF runtime will allow a message to be sent to this specific host
            // This is only needed when the Service address does not map to the certificate, usually in testing
            var epi = EndpointIdentity.CreateX509CertificateIdentity(serviceCert);
            var epa = new EndpointAddress(new Uri(baseAddress), epi, new AddressHeaderCollection());

            var clientBinding = GetClientBinding(injectedCert);
            var channelFactory = new ChannelFactory<IRequestReply>(clientBinding, epa);
            channelFactory.Credentials.ClientCertificate.Certificate = clientCert;
            channelFactory.Credentials.ServiceCertificate.DefaultCertificate = serviceCert;
            channelFactory.Credentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;
            var clientChannel = channelFactory.CreateChannel();
            try
            {
                var outbound = "Client SendString";
                Console.WriteLine($"Client sending: '{outbound}'");
                Console.WriteLine($"Client received: '{clientChannel.SendString(outbound)}'");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception: '{e}'");
            }

            Console.WriteLine("Press a key, to close");
            Console.ReadKey();
        }

        public static Binding GetServiceBinding()
        {
            var serviceBinding = new CustomBinding(GetBindingElements());
            SetMaxTimeout(serviceBinding);
            return serviceBinding;
        }

        public static Binding GetClientBinding(X509Certificate2 certificateToInsert)
        {
            var bindingElements = GetBindingElements(true);
            bindingElements.Insert(bindingElements.Count - 1, new InterceptingBindingElement(certificateToInsert));           
            var customBinding = new CustomBinding(bindingElements);

            SetMaxTimeout(customBinding);
            return customBinding;
        }

        public static BindingElementCollection GetBindingElements(bool addTwo=false)
        {
            var securityBindingElement = SecurityBindingElement.CreateMutualCertificateDuplexBindingElement();
            securityBindingElement.AllowSerializedSigningTokenOnReply = true;
            securityBindingElement.RequireSignatureConfirmation = false;
            securityBindingElement.EndpointSupportingTokenParameters.Signed.Add(new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier));
            if (addTwo)
                securityBindingElement.EndpointSupportingTokenParameters.Signed.Add(new X509SecurityTokenParameters(X509KeyIdentifierClauseType.RawDataKeyIdentifier));

            securityBindingElement.MessageSecurityVersion = MessageSecurityVersion.WSSecurity11WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
            var texMessagingBindingElement = new TextMessageEncodingBindingElement();
            var transportBindingElement = new HttpTransportBindingElement();

            return new BindingElementCollection(new BindingElement[] { securityBindingElement, texMessagingBindingElement, transportBindingElement });
        }

        /// <summary>
        /// Simple helper method to set timeout that is helpful when debugging
        /// </summary>
        /// <param name="binding"></param>
        public static void SetMaxTimeout(Binding binding)
        {
            binding.CloseTimeout = TimeSpan.MaxValue;
            binding.OpenTimeout = TimeSpan.MaxValue;
            binding.ReceiveTimeout = TimeSpan.MaxValue;
            binding.SendTimeout = TimeSpan.MaxValue;
        }
    }

    #region WCF Contracts

    [ServiceContract]
    public interface IRequestReply
    {
        [OperationContract(ProtectionLevel = ProtectionLevel.Sign)]
        string SendString(string message);
    }

    [ServiceBehavior]
    public class RequestReply : IRequestReply
    {
        [OperationBehavior]
        public string SendString(string message)
        {
            string outbound = string.Format("Service received: {0}", message);

            Console.WriteLine("Service received: '{0}'", message);
            Console.WriteLine("Service sending: '{0}'", outbound);

            return outbound;
        }
    }

    #endregion
}
