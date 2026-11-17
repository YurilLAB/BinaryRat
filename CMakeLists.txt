# SPDX-License-Identifier: Apache-2.0
# BinaryRat's C++ build; upstream Ghidra continues to use Gradle.
cmake_minimum_required(VERSION 3.24)
project(BinaryRat VERSION 0.1.0 LANGUAGES CXX)
include(CTest)
add_subdirectory(binaryrat)
