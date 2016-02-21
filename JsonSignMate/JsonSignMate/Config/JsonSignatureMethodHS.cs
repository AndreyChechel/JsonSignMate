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
using System.Security;
using System.Security.Cryptography;

namespace devSane.Json.Config
{
    internal class JsonSignatureMethodHS : JsonSignatureMethod
    {
        private new JsonSignAlgorithmHS Algorithm { get; }
        private readonly SecureString _secret;

        public JsonSignatureMethodHS(JsonSignAlgorithmHS algorithm, SecureString secret)
            : base((JsonSignAlgorithm)algorithm)
        {
            switch (algorithm)
            {
                case JsonSignAlgorithmHS.HS1:
                case JsonSignAlgorithmHS.HS256:
                case JsonSignAlgorithmHS.HS384:
                case JsonSignAlgorithmHS.HS512:
                    break;

                default:
                    throw new ArgumentOutOfRangeException("algorithm");
            }

            throw new NotImplementedException(); // TODO: Clone secret

            Algorithm = algorithm;
            _secret = secret;
        }

        public override string ComputeSignature(byte[] data)
        {
            byte[] signatureBytes;

            using (var hs = CreateHS())
            {
                signatureBytes = hs.ComputeHash(data);
            }

            return Convert.ToBase64String(signatureBytes);
        }

        public override bool ValidateSignature(byte[] data, string signature)
        {
            using (var hs = CreateHS())
            {
                var storedSignature = Convert.FromBase64String(signature);
                var actualSignature = hs.ComputeHash(data);

                if (actualSignature.Length != storedSignature.Length)
                {
                    return false;
                }

                int errCount = 0;
                for (int i = 0; i < actualSignature.Length; i++)
                {
                    if (actualSignature[i] != storedSignature[i])
                    {
                        errCount ++;
                    }
                }
                return errCount == 0;
            }
        }

        public override byte[] ExportKey(bool includePrivateKey)
        {
            throw new NotImplementedException(); // TODO: implement
        }

        private HashAlgorithm CreateHS()
        {
            throw new NotImplementedException(); // TODO: Provide key

            HashAlgorithm sha;
            switch (Algorithm)
            {
                case JsonSignAlgorithmHS.HS1:
                    sha = new HMACSHA1();
                    break;

                case JsonSignAlgorithmHS.HS256:
                    sha = new HMACSHA256();
                    break;

                case JsonSignAlgorithmHS.HS384:
                    sha = new HMACSHA384();
                    break;

                case JsonSignAlgorithmHS.HS512:
                    sha = new HMACSHA512();
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            return sha;
        }
    }
}