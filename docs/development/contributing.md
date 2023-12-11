---
title: Contributing
parent: Development
---

Want to contribute? Great! First, read this page (including the small print at the end).

### Before you contribute
Before we can use your code, you must sign the
[Google Individual Contributor License Agreement](https://developers.google.com/open-source/cla/individual)
(CLA), which you can do online. The CLA is necessary mainly because you own the
copyright to your changes, even after your contribution becomes part of our
codebase, so we need your permission to use and distribute your code. We also
need to be sure of various other things—for instance that you'll tell us if you
know that your code infringes on other people's patents. You don't have to sign
the CLA until after you've submitted your code for review and a member has
approved it, but you must do it before we can put your code into our codebase.

Before you start working on a larger contribution, you should get in touch with
us first through the [issue tracker](https://github.com/google/santa/issues)
with your idea so that we can help out and possibly guide you. Co-ordinating
large changes ahead of time can avoid frustration later on.

### Code reviews
All submissions - including submissions by project members - require review. We
use GitHub pull requests for this purpose. GitHub will automatically run the
tests when you mail your pull request and a proper review won't be started until
the tests are complete and passing.

### Code Style

Santa is written in a mix of C++, Objective-C and a small amount of Rust. All
code submissions should try to match the surrounding code. We follow the [Google
Objective-C Style Guide](https://google.github.io/styleguide/objcguide.xml), the
[Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html) and
the [Rust Style Guide](https://doc.rust-lang.org/beta/style-guide/index.html).

Files containing C++ and Objective-C code are named `ClassName.mm` and
`ClassName.h`. Rust code is named `library_name.rs`. The BUILD rules follow the
same naming convention: `ClassName` for the C-family, and `library_name` or
`library_bridge` (if using cxx) for Rust.

### Using Rust

Rust support in Santa is experimental, and currently only used for specific
external dependencies written in Rust.

Adding new Rust libraries requires some extra steps:

* Each Rust library must have both a `rust_static_library` BUILD target and a
  `Cargo.toml` file listing its dependencies. (`Cargo.toml` helps rust-analyzer
  and VSCode Rust extensions.)
* Each new `Cargo.toml` file must be added to the list in the root `Cargo.toml`
  file AND the `workspace.members` key in the root `WORKSPACE` file.
* Each `rust_static_library` should be wrapped in a `cc_library`, rather than
  depended on directly. (This is quite natural when using `cxx`.)
* Rust code shouldn't be placed just anywhere - generally, each
  `rust_static_library` target should be in a separate directory, with its own
  `Cargo.toml` file. (This lets rust-analyzer understand the code structure.)

Additionally, please follow these guidelines:

* Do not write new Rust code without discussing it with the maintainers first.
* Do not "rewrite it in Rust" for no practical reason.
* Keep the Rust code to the leaves.
* Don't hand over control between Rust and C++ more than absolutely necessary.
* Have C++ call into Rust, not the other way around.
* Don't use cxx to return `Result` types across the FFI. (It might throw a C++
  exception.)
* Run `cargo fix && cargo fmt` before submitting code for review. You may need to run the
  nightly to support all options in `rustfmt.toml`: `rustup run nightly cargo
  fmt`.

### The small print
Contributions made by corporations are covered by a different agreement than
the one above, the [Software Grant and Corporate Contributor License Agreement](https://developers.google.com/open-source/cla/corporate).
