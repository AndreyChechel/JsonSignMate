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
using System.Collections.Generic;
using System.IO;
using System.Text;
using Newtonsoft.Json;

namespace devSane.Json.Internal
{
    internal static class JsonProcessor
    {
        private delegate void JsonReadingNodeHandler(JsonReader reader, bool isRootNode);
        private delegate void JsonWritingNodeHandler(JsonWriter writer);

        public static object[] ReadRootObjProperty(string jsonStr, string propertyName, JsonToken valueType)
        {
            var values = new List<object>();

            ReadNodes(jsonStr, (reader, isRootNode) =>
            {
                if (!isRootNode)
                    return;

                if (reader.TokenType != JsonToken.PropertyName)
                    return;

                if (!string.Equals((string)reader.Value, propertyName, StringComparison.Ordinal))
                    return;

                // Move further to Property value:
                if (!reader.Read())
                {
                    var msg = "Can't read JSON property '" + propertyName + "'. of type '" + valueType + "'.";
                    throw new InvalidOperationException(msg);
                }

                // Validate Value type:
                if (reader.TokenType != valueType)
                {
                    var msg = "JSON property '" + propertyName + "' has invalid value type.";
                    throw new InvalidOperationException(msg);
                }

                values.Add(reader.Value);
            });

            return values.ToArray();
        }

        public static string RemoveRootObjProperties(string jsonStr, params string[] propertyNames)
        {
            var properties = new HashSet<string>(propertyNames, StringComparer.Ordinal);

            var updatedJson = WriteNodes(writer =>
            {
                ReadNodes(jsonStr, (reader, isRootNode) =>
                {
                    if (isRootNode && reader.TokenType == JsonToken.PropertyName)
                    {
                        if (properties.Contains((string)reader.Value))
                        {
                            // Skip this node (property) and it's value
                            reader.Read();
                            return;
                        }
                    }

                    writer.WriteToken(reader, false);
                });
            });

            return updatedJson;
        }

        public static string AppendNodes(string json, Dictionary<string, object> nodes)
        {
            var updatedJson = WriteNodes(writer =>
            {
                ReadNodes(json, (reader, isRootNode) =>
                {
                    if (isRootNode && reader.TokenType == JsonToken.EndObject)
                    {
                        foreach (var node in nodes)
                        {
                            writer.WritePropertyName(node.Key);
                            writer.WriteValue(node.Value);
                        }
                    }

                    writer.WriteToken(reader, false);
                });
            });

            return updatedJson;
        }

        private static string WriteNodes(JsonWritingNodeHandler nodeHandler)
        {
            var sb = new StringBuilder();
            using (var strWriter = new StringWriter(sb))
            {
                var jsonWriter = new JsonTextWriter(strWriter);
                nodeHandler(jsonWriter);
            }
            return sb.ToString();
        }

        private static void ReadNodes(string json, JsonReadingNodeHandler nodeHandler)
        {
            using (var strReader = new StringReader(json))
            {
                var jsonReader = new JsonTextReader(strReader);

                var objNestingLevel = -1;
                while (jsonReader.Read())
                {
                    if (jsonReader.TokenType == JsonToken.StartObject)
                    {
                        objNestingLevel++;
                    }

                    var isRootObj = objNestingLevel == 0;
                    nodeHandler(jsonReader, isRootObj);

                    if (jsonReader.TokenType == JsonToken.EndObject)
                    {
                        objNestingLevel--;
                    }
                }
            }
        }
    }
}