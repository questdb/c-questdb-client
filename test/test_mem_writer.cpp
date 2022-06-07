/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include <string>
#include <limits>

extern "C"
{
#include "../src/mem_writer.h"
}

using namespace std::literals::string_view_literals;

static std::string d2s(double d) {
    mem_writer writer;
    mem_writer_open(&writer, 1024);
    mem_writer_f64(&writer, d);
    size_t len = 0;
    const char* buf = mem_writer_peek(&writer, &len);
    std::string s{buf, len};
    mem_writer_close(&writer);
    return s;
}

TEST_CASE("d2s 0.0")
{
    CHECK(d2s(0.0) == "0.0"sv);
}

TEST_CASE("d2s -0.0")
{
    CHECK(d2s(-0.0) == "-0.0"sv);
}

TEST_CASE("d2s 1.0")
{
    CHECK(d2s(1.0) == "1.0"sv);
}

TEST_CASE("d2s -1.0")
{
    CHECK(d2s(-1.0) == "-1.0"sv);
}

TEST_CASE("d2s 10.0")
{
    CHECK(d2s(10.0) == "10.0"sv);
}

TEST_CASE("d2s 0.1")
{
    CHECK(d2s(0.1) == "0.1"sv);
}

TEST_CASE("d2s 0.01")
{
    CHECK(d2s(0.01) == "0.01"sv);
}

TEST_CASE("d2s 0.000001")
{
    CHECK(d2s(0.000001) == "0.000001"sv);
}

TEST_CASE("d2s -0.000001")
{
    CHECK(d2s(-0.000001) == "-0.000001"sv);
}

TEST_CASE("d2s 100.0")
{
    CHECK(d2s(100.0) == "100.0"sv);
}

TEST_CASE("d2s 1.2")
{
    CHECK(d2s(1.2) == "1.2"sv);
}

TEST_CASE("d2s 1234.5678")
{
    CHECK(d2s(1234.5678) == "1234.5678"sv);
}

TEST_CASE("d2s -1234.5678")
{
    CHECK(d2s(-1234.5678) == "-1234.5678"sv);
}

TEST_CASE("d2s 1.2345678901234567")
{
    CHECK(d2s(1.2345678901234567) == "1.2345678901234567"sv);
}

TEST_CASE("d2s 1000000000000000000000000.0")
{
    CHECK(d2s(1000000000000000000000000.0) == "1000000000000000000000000.0"sv);
}

TEST_CASE("d2s -1000000000000000000000000.0")
{
    CHECK(d2s(-1000000000000000000000000.0) == "-1000000000000000000000000.0"sv);
}

TEST_CASE("d2s qNaN")
{
    double qnan = std::numeric_limits<double>::quiet_NaN();
    CHECK(d2s(qnan) == "NaN"sv);
}

TEST_CASE("d2s -qNaN")
{
    double qnan = - std::numeric_limits<double>::quiet_NaN();
    CHECK(d2s(qnan) == "NaN"sv);
}

TEST_CASE("d2s sNaN")
{
    double snan = std::numeric_limits<double>::signaling_NaN();
    CHECK(d2s(snan) == "NaN"sv);
}

TEST_CASE("d2s -sNaN")
{
    double snan = - std::numeric_limits<double>::signaling_NaN();
    CHECK(d2s(snan) == "NaN"sv);
}

TEST_CASE("d2s Infinity")
{
    double inf = std::numeric_limits<double>::infinity();
    CHECK(d2s(inf) == "Infinity"sv);
}

TEST_CASE("d2s -Infinity")
{
    double inf = -std::numeric_limits<double>::infinity();
    CHECK(d2s(inf) == "-Infinity"sv);
}

TEST_CASE("d2s min")
{
    double min = std::numeric_limits<double>::min();
    CHECK(d2s(min) == ("0.0000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "00000000000000000000000000000000000"
                       "22250738585072014"sv));
}

TEST_CASE("d2s -min")
{
    double min = -std::numeric_limits<double>::min();
    CHECK(d2s(min) == ("-0.0000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "00000000000000000000000000000000000"
                       "22250738585072014"sv));
}

TEST_CASE("d2s max")
{
    double max = std::numeric_limits<double>::max();
    CHECK(d2s(max) == ("179769313486231570000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "00000000000000000000000000000000000.0"sv));
}

TEST_CASE("d2s -max")
{
    double max = -std::numeric_limits<double>::max();
    CHECK(d2s(max) == ("-179769313486231570000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "0000000000000000000000000000000000000000000000000000000"
                       "00000000000000000000000000000000000.0"sv));
}
