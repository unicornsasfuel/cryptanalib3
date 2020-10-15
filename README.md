# cryptanalib3

`cryptanalib3` is a Python3 fork of the `cryptanalib` module from the FeatherDuster project, meant to be a standalone set of tools for performing cryptanalysis work.

Since Python3 forces a choice between bytes and string objects, cryptanalib3 now operates entirely on bytes objects in order to avoid the various ways in which Python manipulates strings to try to ensure the data is readable in the user's locale. All functions that consumed and return strings in the original Cryptanalib now receive and return bytes objects.

This project is passing all tests, but still needs a lot of cleanup.

## Usage

```
>>> import ca3
>>> ca3.analyze_ciphertext(b'gdkkn')
...
>>> ca3.break_alpha_shift(b'gdkkn')
