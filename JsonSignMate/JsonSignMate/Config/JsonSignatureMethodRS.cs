/*
Copyright 2016 Andrey Chechel

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

using System;
using System.Security.Cryptography;
using devSane.Json.Internal;

namespace devSane.Json.Config
{
    internal class JsonSignatureMethodRS : JsonSignatureMethod
    {
        private new JsonSignAlgorithmRS Algorithm { get; }
        private readonly RSAParameters _rsaParameters;

        public JsonSignatureMethodRS(JsonSignAlgorithmRS algorithm, RSAParameters rsaParameters)
            : base((JsonSignAlgorithm) algorithm)
        {
            switch (algorithm)
            {
                case JsonSignAlgorithmRS.RS1:
                case JsonSignAlgorithmRS.RS256:
                case JsonSignAlgorithmRS.RS384:
                case JsonSignAlgorithmRS.RS512:
                    break;

                default:
                    throw new ArgumentOutOfRangeException("algorithm");
            }

            Algorithm = algorithm;
            _rsaParameters = rsaParameters;
        }

        public override string ComputeSignature(byte[] data)
        {
            byte[] signatureBytes;

            using (var rs = CreateRS())
            {
                using (var sha = CreateSHA())
                {
                    rs.ImportParameters(_rsaParameters);
                    signatureBytes = rs.SignData(data, sha);
                }
            }

            return Convert.ToBase64String(signatureBytes);
        }

        public override bool ValidateSignature(byte[] data, string signature)
        {
            var storedSignatureBytes = Convert.FromBase64String(signature);

            using (var rs = CreateRS())
            {
                using (var sha = CreateSHA())
                {
                    rs.ImportParameters(_rsaParameters);
                    var isValid = rs.VerifyData(data, sha, storedSignatureBytes);
                    return isValid;
                }
            }
        }

        public override byte[] ExportKey(bool includePrivateKey)
        {
            using (var rs = CreateRS())
            {
                rs.ImportParameters(_rsaParameters);
                var exportingRsa = rs.ExportParameters(includePrivateKey);
                var exportingRsaBytes = JsonProcessor.Serialize(exportingRsa);
                return exportingRsaBytes;
            }
        }

        private RSACryptoServiceProvider CreateRS()
        {
            var rs = new RSACryptoServiceProvider();
            rs.ImportParameters(_rsaParameters);
            return rs;
        }

        private HashAlgorithm CreateSHA()
        {
            HashAlgorithm sha;
            switch (Algorithm)
            {
                case JsonSignAlgorithmRS.RS1:
                    sha = new SHA1CryptoServiceProvider();
                    break;

                case JsonSignAlgorithmRS.RS256:
                    sha = new SHA256CryptoServiceProvider();
                    break;

                case JsonSignAlgorithmRS.RS384:
                    sha = new SHA384CryptoServiceProvider();
                    break;

                case JsonSignAlgorithmRS.RS512:
                    sha = new SHA512CryptoServiceProvider();
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            return sha;
        }
    }
}