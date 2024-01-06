
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "api.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(char *S, unsigned char *A, unsigned long long L);



static int kyber_Attack() {

    /*pk sk ct*/
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES];

    /* the s  recovered by adversary */
    signed char         recs[KYBER_K][KYBER_N] = { 0 };
    /* the polyvec form of true s */
    polyvec             skpoly = { { 0 } };
    /* the m set by adversary */
    unsigned char       m[KYBER_SYMBYTES]  = { 0 };
    m[0] = 0x1;         // first coeff of m is 1

    /* get key pair */
    if (  crypto_kem_keypair(pk, sk, &skpoly) != 0 ) {
        printf("crypto_kem_keypair error\n");
        return KAT_CRYPTO_FAILURE;
    }

    
    int h ;         //parameter
    int query = 0;

    for(int i = 0; i < KYBER_K; i++) { // KYBER_K
        for(int k = 0; k < KYBER_N; k++) { // KYBER_N

	   kemenc_Attack(ct, m, 665, 2, k, i);
	   if(oracle(ct, sk, m, k, i) == 1) {
		query += 1;
		kemenc_Attack(ct, m, 499, 0, k, i);
		if(oracle(ct, sk, m, k, i) == 0) {
		    recs[i][k] = -1;
		    query += 1;
		}
		else{
		    query += 1;
		    kemenc_Attack(ct, m, 499, 2, k, i);
		    if(oracle(ct, sk, m, k, i) == 0) {
			recs[i][k] = 2;
			query += 1;
		    }
		    else{
			query += 1;
                        kemenc_Attack(ct, m, 332, 0, k, i);
                        if(oracle(ct, sk, m, k, i) == 0) {
                            recs[i][k] = -2;
                            query += 1;
                        }
			else{
			    query += 1;
                            kemenc_Attack(ct, m, 166, 4, k, i);
                            if(oracle(ct, sk, m, k, i) == 0) {
                                recs[i][k] = 3;
                                query += 1;
                            }
			    else{
		                recs[i][k] = -3;
		                query += 1;
		           }
			}
		    }
		}
	   }
	   else{
		query += 1;
                kemenc_Attack(ct, m, 1664, 0, k, i);
                if(oracle(ct, sk, m, k, i) == 0) {
                    recs[i][k] = 0;
                    query += 1;
                }
	        else{
                    recs[i][k] = 1;
                    query += 1;
               }
           }

        }
    }

   /* check the recs recovere by adversary  ==  the true s */
   int checks = 0;
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j++) {
            if(recs[i][j] != skpoly.vec[i].coeffs[j]) {
                checks++;
                printf("error s in s[%d][%d] ", i, j);
            }
        }   
    }


    /* print the queries */
    if(checks == 0)
        printf("fact queries: %d\n", query);
    else 
        printf("not correct\n");
    return query;
}


int
main(int argc, char * argv[])
{

    if(argc == 1) {
        printf("Input the test times\n");
        return 0;
    }
    //get the test times
    int rand = atoi(argv[1]);
    
    /* random init */
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    for (int i=0; i<48; i++)
	entropy_input[i] = i;
    randombytes_init(entropy_input, NULL, 256);

    /* start attack */    
    int sum = 0;
    for(int i=1;i<=rand;i++){
        randombytes(seed, 48);
        fprintBstr("\nseed = ", seed, 48);
        randombytes_init(seed, NULL, 256);
	sum += kyber_Attack();
    }
    printf("\nEX_query = %f\n",sum*1.0/rand);    
    return 0;

}


void
fprintBstr(char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	printf("%s", S);

	for ( i=0; i<L; i++ )
		printf("%02X", A[i]);

	if ( L == 0 )
		printf("00");

	printf("\n");
}

