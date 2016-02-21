using System.Security;
using System.Security.Cryptography;
using devSane.Json.Internal;

namespace devSane.Json
{
    public class JsonSignMateFactory
    {
        internal JsonSignMateFactory()
        {
        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm, RSAParameters rsaParameters)
        {
            var method = new JsonSignMethodRS(algorithm, rsaParameters);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm, byte[] rsaParametersBytes)
        {
            var rsaParameters = JsonProcessor.Deserialize<RSAParameters>(rsaParametersBytes);
            return CreateRS(algorithm, rsaParameters);

        }

        public JsonSignMate CreateRS(JsonSignAlgorithmRS algorithm)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                return CreateRS(algorithm, rsa.ExportParameters(true));
            }
        }

        public JsonSignMate CreateHS(JsonSignAlgorithmHS algorithm, SecureString secret)
        {
            var method = new JsonSignMethodHS(algorithm, secret);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm, CngKey key)
        {
            var method = new JsonSignMethodES(algorithm, key);
            var config = new JsonSignMateConfig { Method = method };
            return new JsonSignMate(config);
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm, byte[] keyBytes)
        {
            using (var key = CngKey.Import(keyBytes, CngKeyBlobFormat.EccPrivateBlob))
            {
                return CreateES(algorithm, key);
            }
        }

        public JsonSignMate CreateES(JsonSignAlgorithmES algorithm)
        {
            using (var es = new ECDsaCng())
            {
                return CreateES(algorithm, es.Key);
            }
        }
    }
}