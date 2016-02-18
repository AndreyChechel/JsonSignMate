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

namespace devSane.Json.Internal
{
    internal static class SignatureProcessor
    {
        public static string Calculate(string json, string secret)
        {
            var secretBytes = Encoding.Unicode.GetBytes(secret);
            using (var hs256 = new HMACSHA256(secretBytes))
            {
                var bytes = Encoding.Unicode.GetBytes(json);
                var hash = hs256.ComputeHash(bytes);
                return Convert.ToBase64String(hash);
            }
        }
    }
}