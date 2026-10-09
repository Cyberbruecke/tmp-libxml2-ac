#!/usr/bin/env python3
"""Enable SlowFuzz's own custom-mutator hook (the slowfuzz-suite configuration).

SlowFuzz ships the hook commented out under a FIXME (Fuzzer/FuzzerMutate.cpp:55-61,
72-78) because it does not compile: Mutate_Custom returns size_t, while Mutator::Fn
returns std::tuple<size_t,size_t,size_t> (FuzzerMutate.h:36, :113-117). This fixes
the signature and registers the mutator. It adds no mutation logic; the mutations
come from the suite, supplied through LLVMFuzzerCustomMutator.

Each edit must match exactly once, so a different SlowFuzz revision fails loudly
rather than being partly patched.
"""
import re
import sys

cpp_path, h_path = sys.argv[1], sys.argv[2]


def sub1(pat, repl, what, txt, flags=re.M):
    out, n = re.subn(pat, repl, txt, flags=flags)
    assert n == 1, "%s: expected 1 match, got %d" % (what, n)
    return out


# (a) header: Mutate_Custom must return the same 3-tuple as every other mutator.
h = open(h_path).read()
h = sub1(r'^  size_t  Mutate_Custom\(',
         '  std::tuple<size_t, size_t, size_t>  Mutate_Custom(',
         "header decl", h)
open(h_path, 'w').write(h)

s = open(cpp_path).read()

# (b) definition returns <MutationStart, MutationLength, NewSize>. The suite can
#     rewrite anywhere in the buffer, so the extent is the whole new buffer.
s = sub1(r'^size_t\n(MutationDispatcher::Mutate_Custom\()',
         r'std::tuple<size_t, size_t, size_t>\n\1', "return type", s)
s = sub1(r'^(\s*)return EF->LLVMFuzzerCustomMutator\(Data, Size, MaxSize, Rand\.Rand\(\)\);',
         r'\1size_t NewSize = EF->LLVMFuzzerCustomMutator(Data, Size, MaxSize, Rand.Rand());'
         '\n' r'\1return std::make_tuple((size_t) 0, NewSize, NewSize);',
         "body", s)

# (c) register it. The name must be numeric: GetLastMutationIdx() does std::stoi(Name)
#     (FuzzerMutate.cpp:557) and is called unconditionally from FuzzerLoop.cpp:801 and :813.
#     DefaultMutators are named "0".."12", so the suite becomes "13".
s = sub1(r'^  // if \(EF->LLVMFuzzerCustomMutator\)\n'
         r'    // Mutators\.push_back\(\{&MutationDispatcher::Mutate_Custom, "Custom"\}\);\n'
         r'  // else\n'
         r'    Mutators = DefaultMutators;$',
         '    Mutators = DefaultMutators;\n'
         '    if (EF->LLVMFuzzerCustomMutator)\n'
         '      Mutators.push_back({&MutationDispatcher::Mutate_Custom, "13"});',
         "Mutators init block", s)

# (d) the score vector must cover the registered menu, not just the default one.
s = sub1(r'MutatorScores = std::vector<uint64_t>\(DefaultMutators\.size\(\), 0\);',
         'MutatorScores = std::vector<uint64_t>(Mutators.size(), 0);',
         "MutatorScores sizing", s)

# (e) the two asserts were off by one and checked the wrong vector.
n = s.count('assert(idx <= DefaultMutators.size()')
assert n == 2, "expected 2 asserts, got %d" % n
s = s.replace('assert(idx <= DefaultMutators.size()', 'assert(idx < Mutators.size()')

open(cpp_path, 'w').write(s)
print("  patched: 6 edits across FuzzerMutate.{h,cpp}")
