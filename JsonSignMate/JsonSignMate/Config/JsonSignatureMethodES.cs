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

namespace devSane.Json.Config
{
    internal class JsonSignatureMethodES : JsonSignatureMethod
    {
        private new JsonSignAlgorithmES Algorithm { get; }
        private readonly CngKey _key;

        public JsonSignatureMethodES(JsonSignAlgorithmES algorithm, CngKey key)
            : base((JsonSignAlgorithm)algorithm)
        {
            switch (algorithm)
            {
                case JsonSignAlgorithmES.ES1:
                case JsonSignAlgorithmES.ES256:
                case JsonSignAlgorithmES.ES384:
                case JsonSignAlgorithmES.ES512:
                    break;

                default:
                    throw new ArgumentOutOfRangeException("algorithm");
            }

            throw new NotImplementedException(); // TODO: Clone key

            Algorithm = algorithm;
            _key = key;
        }

        public override string ComputeSignature(byte[] data)
        {
            byte[] signatureBytes;

            using (var es = CreateES())
            {
                signatureBytes = es.SignData(data);
            }

            return Convert.ToBase64String(signatureBytes);
        }

        public override bool ValidateSignature(byte[] data, string signature)
        {
            using (var es = CreateES())
            {
                var storedSignature = Convert.FromBase64String(signature);
                var actualSignature = es.SignData(data);

                if (actualSignature.Length != storedSignature.Length)
                {
                    return false;
                }

                int errCount = 0;
                for (int i = 0; i < actualSignature.Length; i++)
                {
                    if (actualSignature[i] != storedSignature[i])
                    {
                        errCount++;
                    }
                }
                return errCount == 0;
            }
        }

        public override byte[] ExportKey(bool includePrivateKey)
        {
            return _key.Export(includePrivateKey ? CngKeyBlobFormat.EccPrivateBlob : CngKeyBlobFormat.EccPublicBlob);
        }

        private ECDsaCng CreateES()
        {
            var es = new ECDsaCng(_key);

            switch (Algorithm)
            {
                case JsonSignAlgorithmES.ES1:
                    es.HashAlgorithm = CngAlgorithm.Sha1;
                    break;

                case JsonSignAlgorithmES.ES256:
                    es.HashAlgorithm = CngAlgorithm.Sha256;
                    break;

                case JsonSignAlgorithmES.ES384:
                    es.HashAlgorithm = CngAlgorithm.Sha384;
                    break;

                case JsonSignAlgorithmES.ES512:
                    es.HashAlgorithm = CngAlgorithm.Sha512;
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            return es;
        }
    }
}