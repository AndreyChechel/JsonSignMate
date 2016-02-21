﻿/*
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

namespace devSane.Json.Config
{
    public enum JsonSignAlgorithm
    {
        HS1   = JsonSignAlgorithmHS.HS1,
        HS256 = JsonSignAlgorithmHS.HS256,
        HS384 = JsonSignAlgorithmHS.HS384,
        HS512 = JsonSignAlgorithmHS.HS512,

        RS1   = JsonSignAlgorithmRS.RS1,
        RS256 = JsonSignAlgorithmRS.RS256,
        RS384 = JsonSignAlgorithmRS.RS384,
        RS512 = JsonSignAlgorithmRS.RS512,

        ES1   = JsonSignAlgorithmES.ES1,
        ES256 = JsonSignAlgorithmES.ES256,
        ES384 = JsonSignAlgorithmES.ES384,
        ES512 = JsonSignAlgorithmES.ES512,
    }

    public enum JsonSignAlgorithmHS
    {
        HS1 = 100,
        HS256,
        HS384,
        HS512
    }

    public enum JsonSignAlgorithmRS
    {
        RS1 = 200,
        RS256,
        RS384,
        RS512
    }

    public enum JsonSignAlgorithmES
    {
        ES1 = 300,
        ES256,
        ES384,
        ES512
    }
}