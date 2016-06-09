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
with your idea so that we can help out and possibly guide you. Coordinating up 
front makes it much easier to avoid frustration later on.

### Code reviews
All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. It's also a good idea to run the
tests beforehand, which you can do with the following commands:

```sh
rake tests:logic
rake tests:kernel  # only necessary if you're changing the kext code
```
### Code Style

All code submissions should try to match the surrounding code.  Wherever possible,
code should adhere to either the
[Google Objective-C Style Guide](https://google.github.io/styleguide/objcguide.xml)
or the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).

### The small print
Contributions made by corporations are covered by a different agreement than
the one above, the [Software Grant and Corporate Contributor License Agreement](https://developers.google.com/open-source/cla/corporate).
