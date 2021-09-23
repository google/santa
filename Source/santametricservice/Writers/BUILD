load("//:helper.bzl", "santa_unit_test")

package(default_visibility = ["//:santa_package_group"])

licenses(["notice"])

objc_library(
    name = "SNTMetricWriter",
    hdrs = ["SNTMetricWriter.h"],
)

objc_library(
    name = "SNTMetricFileWriter",
    srcs = [
        "SNTMetricFileWriter.h",
        "SNTMetricFileWriter.m",
        "SNTMetricWriter.h",
    ],
    deps = [
        ":SNTMetricWriter",
        "//Source/common:SNTLogging",
    ],
)

santa_unit_test(
    name = "SNTMetricFileWriterTest",
    srcs = [
        "SNTMetricFileWriterTest.m",
    ],
    deps = [
        ":SNTMetricFileWriter",
    ],
)
