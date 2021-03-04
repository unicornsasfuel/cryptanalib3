This project has several goals you should keep in mind when submitting any code. It is meant to be useful as both a library built into other tools and in an interactive terminal. It should be usable on a variety of OSes and platforms including those supporting only pure Python. Pure Python means it should run on PyPy, for speed-critical attacks, and on Jython to allow cryptanalib3 to be used in Burp Suite extensions.

## Please
- Submit tests with any new functionality.
- Document inputs, outputs, and purpose of any new function in its docstring.
- Avoid adding dependencies unless it's really necessary.
- If you must add additional dependencies, please ensure they are pure Python.
- Put new functions in the appropriate place:
   - classical.py for attacking ciphers you'd find in puzzle or history books
   - modern.py for attacking ciphers meant to protect real-world data today
   - helpers.py for functions that are not attacks, but may be useful in constructing attacks
- Submit only code that is written by you, or that is compatible with the BSD 3-clause license.
- Submit only pull requests that pass all existing tests.
