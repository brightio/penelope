# Contributing to Penelope

Thanks for your interest in contributing! A few principles shape what fits the
project, so reading this first will save us both some back-and-forth.

## Design principles

- **Standard library only.** Penelope runs as a single script with no
  installation, often somewhere you can't `pip install` anything. A feature that
  needs a third-party package is a big ask. If you think one is warranted, open
  an issue to discuss it before writing the code.
- **Python 3.6+.** Avoid syntax and stdlib features newer than 3.6. Check before
  relying on something recent.
- **Unix-like handler.** The handler runs on Linux and macOS. It manages shells
  from Windows targets but isn't meant to run on Windows itself.
- **Single script.** Keep changes self-contained rather than splitting things
  into new modules.

## Issues

Please use the templates instead of a blank issue. Bug reports should include
your Penelope version, install method, the Python version and OS running
Penelope, the mode in use, the exact command, and expected vs. actual behavior.
Feature requests should describe the problem before the solution. For usage
questions, use Discussions.

**Security vulnerabilities:** do not open a public issue. See
[SECURITY.md](SECURITY.md) for private reporting.

## Pull requests

1. Keep it focused, one logical change per PR.
2. Match the existing style. Penelope uses tabs; don't reformat surrounding code.
3. Test it and say how, including the OS, Python version, and mode you tested
   (reverse/bind, Unix/Windows target, raw/PTY). Test on older Python where you
   can.
4. Update the README or help text if usage changes.
5. Fill in the PR template.

Test on two separate machines (one running Penelope, one acting as the target)
rather than a single local host, since that's how the tool is actually used. At
a minimum, exercise the function you changed; ideally check that the other
functions still work too, so your change doesn't break anything elsewhere.

`python3 penelope.py --help` is a fast way to confirm the script still runs on a
given Python version.

## License

Penelope is licensed under GPL-3.0-or-later. By contributing, you agree your
contributions are licensed under the same terms.
