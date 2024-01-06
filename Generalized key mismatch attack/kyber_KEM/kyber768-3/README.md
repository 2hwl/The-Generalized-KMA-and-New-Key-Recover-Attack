This is the demo for Kyber768 in NIST Round 3.

# Structure

PQCgenKAT_kem.c: the entrance of attack, 

kem.c:  building the oracle 

indcpa.c: choosing attack parameters


# Build and Run

To build it, you need to have openssl  and make on linux or Mac os.

> make

After making, then you can run 

>  ./PQCgenKAT_kem \<num1\> \<num2\>

`<num1>` is an integer that represents the number of tests. 
`<num2>` is an integer that represents the number of leakaged positions.

For example, `./PQCgenKAT_kem 1000 2`
