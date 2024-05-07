C implementation of SHA-256 hashing algorithm, from the SHA-2 (Secure Hash Algorithm 2) family.

This my first time writing an "actual thing" in C, something that isn't me just messing around and experimenting with how stuff works with a couple of lines of code, so I apologize in advance if you attempt to read this code. It is almost certainly a mess lol.

# Sources used:
I followed the pseudocode from the SHA-2 Wikipedia page found here: https://en.wikipedia.org/wiki/SHA-2#Pseudocode

I also used https://sha256algorithm.com/ to visualize how the message block was constructed, because at some point my code worked correctly if you gave it an empty string, but not a non-empty string. This was due to me writing the 64-bit big-endian integer at the end of the initial message block incorrectly.
