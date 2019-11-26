<!-- $theme: default -->

Spitfire Specs
---------

<img src="images/spitfire.jpg" alt="drawing" width="400"/>

Tim Leek
Andy Davis
Heather Preslier
Chris Connelly
12/5/2019

---

## Introduction

Spitfire is a fuzzer framework.  Its purpose is to enable repeatable experiments.  

---

## Goals / Decisions:

<span style="font-size:80%">

* Tools consume inputs and generate outputs in standard formats
* Results and fuzzing experiment information made available in a `knowledge_base`
* Spitfire codebase will include experiments that can be checked out and run to reproduce results.
* Tool settings as well as code versions will be documented in `knowledge_base` in order that results can be repeated.
* Existing tools can be shimmed to conform to Spitfire's interfaces (Angr, Triton, Panda, etc)
* Existing fuzzers can be `implemented` with Spitfire. This means creating a `fuzzing_manager` that instantiates mutational and grammar based fuzzers, employs taint and symbolic execution selectively, and generally manages the temporal fuzzing campaign 
* All tools are required to run and then quit (no tools that run forever)

</span>

----

## Mutational fuzzer tool Interface

<span style="font-size:60%">

| I/O    | Name                 | Type             | Required? | Comment    |
|:------ |:--------------------:|:----------------:|:---------:|------------|
| input  | `input_file`         | `File`           | Yes       |            |
| input  | `max_fuzzed_files`   | `Integer`        | No        |            |
| input  | `timeout`            | `Integer`        | No        | in seconds |
| output | `interesting_files`  | `File Array`     | Yes       |            |
| output | `why_interesting`    | `Interest Array` | Yes       | one per `fuzzed_file` |
| output | `marginal_coverage`  | `Coverage Array` | No        | one per `fuzzed_file` |
| output | `global_coverage`    | `Coverage`       | No        |            |


Notes:
* `max_fuzzed_files` and `timeout` will have defaults, which is why they are not required
* `Interest` is a set of possible detector outputs (new coverage, exceptions, ASAN output, assertions, etc)
* `Coverage` is a binary output format for coverage info (more later)
* `marginal_coverage` is the coverage unique to this file
* `global_coverage` is the union of coverage for all `fuzzed_files`

</span>


---

## Grammar-based fuzzer tool Interface

<span style="font-size:60%">

| I/O    | Name                | Type             | Required? | Comment    |
|:------ |:-------------------:|:----------------:|:---------:|------------|
| input  | `max_fuzzed_files`  | `Integer`        | No        |            |
| input  | `timeout`           | `Integer`        | No        | in seconds |
| output | `interesting_files` | `File Array`     | Yes       |            |
| output | `why_interesting`   | `Interest Array` | Yes       | one per `fuzzed_file` |
| output | `marginal_coverage` | `Coverage Array` | No        | one per `fuzzed_file` |
| output | `global_coverage`   | `Coverage`       | No        |            |

Notes:
* No `input_file` here
* There is a grammar, but this isn't really an input and there's no benefit in standardizing
* Output is same as mutational fuzzer

</span>

---

## Taint analysis tool Interface

<span style="font-size:60%">

| I/O    | Name                  | Type                             | Required?  | Comment    |
|:------ |:---------------------:|:--------------------------------:|:----------:|------------|
| input  | `input_file`          | `File`                           | Yes        |            |
| input  | `timeout`             | `Integer`                        | No         | in seconds |
| output | `tainted_intructions` | `TaintedInstruction Array`              | Yes        |            |
| output | `file_extents`        | `FileExtent Array`               | Yes        |            |
| output | `taint_map`           | `TaintedInstruction * FileExtent Array` | Yes        |            | 
| output | `tcns`                | `Integer Array`                  | No         |            |

Notes:
* `tainted_instruction` TaintedInstruction` is an instruction in the target program seen to be tainted
* `FileExtent` is some positional bytes in the file that are seen to taint an attack point at some instant in the trace
* `taint_map` is sparse matrix mapping `FileExtent`s to `AttackPoints`
* `tcns` are a companion to `taint_map` (same length) indicating computational distance of tainted instruction at attack point from inputs

</span>

---

## Symbolic execution tool Interface

<span style="font-size:60%">

| I/O    | Name                | Type                  | Required?  | Comment              |
|:------ |:-------------------:|:---------------------:|:----------:|----------------------|
| input  | `input_file`        | `File`                | Yes        |                      |
| input  | `timeout`           | `Integer`             | No         | in seconds           |
| output | `solve_files`       | `File Array`          | Yes        |                      |
| output | `path_constraints`  | `ConstraintSet Array` | No         | one per `solve_file` | 

Notes:
* A `solve_file` is an input file  created via symbolic execution + solving that achieves some new coverage
* `ConstraintSet` is a companion array to `solve_files` (same length), providing path constraints fed to solver

</span>


---

## Coverage

The `Coverage` type is a tuple of various kinds of coverage. Each element in the tuple is optional. However, it is required that at least one kind of coverage is provided.

* `BlockCoverage` is set of basic blocks covered, with counts
* `EdgeCoverage of Integer` is the set of n-edges (n is the `Integer`) covered, with counts. An `Edge` is a pair of `Integers` representing a transition observed between two basic blocks.

Other kinds of coverage are possible, including state coverage.  We will tackle these later.

---

## Persistent `knowledge_base`

Spitfire will be implemented such that most compute happens on the cloud. Each tool run (required to be finite in time) will be required to deposit its results in a persistent knowledge store. 
* Could be database or a key-value store or whatever
* Lincoln will implement libraries in C and Python to marshall and unmarshall the various data types (`AttackPoint`, `Coverage`, etc) to a few different knowledge bases.

---
## Persistent filesystem

We also need a filesystem.  For stuff that wouldn't make sense to put in a knowledge base.  All cloud instances will mount this volume and will be able to refer to files with consistent path names.

* All `Files` from fuzzing or symbolic exec / solving
* PANDA recordings
