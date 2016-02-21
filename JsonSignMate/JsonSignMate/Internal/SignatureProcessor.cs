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
using System.Text;
using devSane.Json.Config;

namespace devSane.Json.Internal
{
    internal static class SignatureProcessor
    {
        public static JsonSignInfo Calculate(string json, JsonSignatureMethod method)
        {
            string signature;

            var jsonBytes = Encoding.Unicode.GetBytes(json);
            var secretBytes = Encoding.Unicode.GetBytes(secret);

            switch (algorithm)
            {
                case JsonSignAlgorithm.HMACSHA256:
                    signature = CalculateHMACSHA256(jsonBytes, secretBytes);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(algorithm));
            }

            var result = new JsonSignInfo {Algorithm = algorithm, Signature = signature};
            return result;
        }

        private static string CalculateHMACSHA1(byte[] data, byte[] secret)
        {
            using (var hs1 = new HMACSHA1(secret))
            {
                var hash = hs1.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
        }

        private static string CalculateHMACSHA256(byte[] data, byte[] secret)
        {
            using (var hs256 = new HMACSHA256(secret))
            {
                var hash = hs256.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
        }

        private static string CalculateHMACSHA384(byte[] data, byte[] secret)
        {
            using (var hs384 = new HMACSHA384(secret))
            {
                var hash = hs384.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
        }

        private static string CalculateRSASHA1(byte[] data, byte[] privateRsaParameters)
        {
            using (var rs1 = new RSACryptoServiceProvider())
            {
                rs1.FromXmlString(privateKeyXml);

                using (var s1 = new SHA1CryptoServiceProvider())
                {
                    
                }
            }


            using (var hs512 = new HMACSHA512(secret))
            {
                var hash = hs512.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
        }

        private static string CalculateHMACSHA512(byte[] data, byte[] secret)
        {
            var rsa = new RSACryptoServiceProvider();
            using (var hs512 = new re(secret))
            {
                var hash = hs512.ComputeHash(data);
                return Convert.ToBase64String(hash);
            }
        }
    }
}