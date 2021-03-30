# Simon-Speck-Lightweight-Block-Ciphers
Implementation of a basic Simon Cipher round key finder using Differential Trail Analysis and Differential Trails.

Uses an efficient one-bit flip fault model, and constructed differential trail tables, at round T-5 to obtain the last 4 round keys first, before using the key schedule to find all other round keys.  (Methodology can be found in attached PDF file)

Run in conjunction with simonfault cipher class (found in *Simon_fault.py*), which simulates fault injection at round T-5.



