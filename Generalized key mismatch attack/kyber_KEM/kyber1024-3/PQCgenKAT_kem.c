
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
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


/********** Attack *************/
static int kyber_Attack(int P) {
    
    

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
    
    int h ;   //parameter
    int query = 0;
    //int P = 2;
    int C2[KYBER_N] = {0};
    int C3[KYBER_N] = {0};
    int Che[KYBER_K][KYBER_N][5] = {{0}};
    int index[KYBER_N] = {0};
    

    // Step 1
    memset(C2, 0, sizeof(C2));
    for(int i = 0; i < KYBER_K; i++) {
        for(int k = 0; k < KYBER_N; k+=P) {
        
	    // STEP 1
            for(int t=0;t<P;t++){
            	C2[k+t] = 8;
            }
            kemenc_Attack(ct, m, 104, C2, k, i, P); 
            query += 1;
            oracle(ct, sk, m, k, P, C3);
            
            for(int t=k;t<k+P;t++){
            	if(C3[t] == 0) recs[i][t] = 12;
            	else recs[i][t] = 11;
            }
        }
    }
    
    // Step 2
    for(int i = 0; i < KYBER_K; i++) {
        for(int j = 0; j < KYBER_N; j ++ ) {
                    
    	    int flag = 0;
    	    memset(index, 0, sizeof(index));
    	    int cnt = 0;
    	    if(recs[i][j] == 11){
    	    
    	    	for(int k=j+1;k<KYBER_N;k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(recs[i][k] == 11){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	memset(C2, 0, sizeof(C2));
    	    	C2[j] = 7;
    	    	for(int k=0; k<cnt; k++)
    	    	  C2[index[k]] = 7;
    	    	  
    	    	kemenc_Attack(ct, m, 104, C2, j, i, -1); 
		query += 1;
		oracle(ct, sk, m, j, -1, C3);
		
    	    	if(C3[j] == 0) recs[i][j] = -1;
    	    	else recs[i][j] = -2;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k=0; k<cnt; k++){
    	    	      if(C3[index[k]] == 0) recs[i][index[k]] = -1;
    	    	      else recs[i][index[k]] = -2;
    	    	    }
    	    	}
    	    }
    	    
        }
    }
    
    // STEP 3
    for(int i=0;i<KYBER_K;i++){
    	for(int j=0; j<KYBER_N; j++){
    	    int flag = 0;
    	    memset(index, 0, sizeof(index));
    	    int cnt = 0;
    	    if(recs[i][j] == 12){
    	    
    	    	for(int k=j+1;k<KYBER_N;k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(recs[i][k] == 12){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	memset(C2, 0, sizeof(C2));
    	    	C2[j] = 9;
    	    	for(int k=0; k<cnt; k++)
    	    	  C2[index[k]] = 9;
    	    	  
    	    	kemenc_Attack(ct, m, 104, C2, j, i, -1); 
		query += 1;
		oracle(ct, sk, m, j, -1, C3);
		
    	    	if(C3[j] == 0) recs[i][j] = 13;
    	    	else recs[i][j] = 0;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k=0; k<cnt; k++){
    	    	      if(C3[index[k]] == 0) recs[i][index[k]] = 13;
    	    	      else recs[i][index[k]] = 0;
    	    	    }
    	    	}
    	    }
    	}
    }
    
    // STEP 4
    for(int i=0;i<KYBER_K;i++){
    	for(int j=0; j<KYBER_N; j++){
    	    int flag = 0;
    	    memset(index, 0, sizeof(index));
    	    int cnt = 0;
    	    if(recs[i][j] == 13){
    	    
    	    	for(int k=j+1;k<KYBER_N;k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(recs[i][k] == 13){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	memset(C2, 0, sizeof(C2));
    	    	C2[j] = 10;
    	    	for(int k=0; k<cnt; k++)
    	    	  C2[index[k]] = 10;
    	    	  
    	    	kemenc_Attack(ct, m, 104, C2, j, i, -1); 
		query += 1;
		oracle(ct, sk, m, j, -1, C3);
		
    	    	if(C3[j] == 0) recs[i][j] = 2;
    	    	else recs[i][j] = 1;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k=0; k<cnt; k++){
    	    	      if(C3[index[k]] == 0) recs[i][index[k]] = 2;
    	    	      else recs[i][index[k]] = 1;
    	    	    }
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
                printf("error s in s[%d][%d] \n", i, j);
                printf("recs[%d][%d] = %d \n", i, j, recs[i][j]);
                printf("Sk[%d][%d] = %d \n", i, j, skpoly.vec[i].coeffs[j]);
            }
        }   
    }
    /* print the queries */
    if(checks == 0)
    {
        printf("fact queries: %d\n", query);
    	return query;
    }
    else 
        printf("not correct\n Error = %d\n", checks);
    return 0;
}


int main(int argc, char * argv[])
{
    if(argc == 1) {
        printf("Input the test times\n");
        return 0;
    }
    //get the test times
    int rand = atoi(argv[1]);
    int P = atoi(argv[2]);
    
    
    /* random init */
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    for (int i=0; i<48; i++)
	entropy_input[i] = i;
	
    randombytes_init(entropy_input, NULL, 256);


    /* start attack */
    int sum = 0;
    int pro = rand;
    for(int i=0;i<rand;i++){
    
        randombytes(seed, 48);
        fprintBstr("\nseed = ", seed, 48);
        randombytes_init(seed, NULL, 256);
	int temp = kyber_Attack(P);
	if(temp == 0)
		pro -= 1;
	sum += temp;
    }
    printf("\nEX_query = %f\n",sum*1.0/rand); 
    printf("Success = %f\n",pro*1.0/rand); 
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



