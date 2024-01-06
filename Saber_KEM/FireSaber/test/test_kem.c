#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "../pack_unpack.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>


void	fprintBstr(char *S, unsigned char *A, unsigned long long L);
static int test_pke_cpa(int P)
{
    //key mismatch attack on Firesaber
    // parameters: res: b'
    //          vprime: cm
    //            ss_a: message
    //	         query: count the total queries
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
    uint16_t res[SABER_L][SABER_N];
    int sk_hat[SABER_L][SABER_N] = {0};
    uint16_t vprime[SABER_N];
    uint8_t msg[SABER_N];
    uint16_t sksv[SABER_L][SABER_N]; //secret key of the server
    int query=0;
    
    //Generation of secret key sk and public key pk pair
    crypto_kem_keypair(pk, sk);
    BS2POLVECq(sk, sksv); //sksv is the secret-key
    int che[4][256][2];
    int index[SABER_N];
    memset(che,0,sizeof(che));

    for(int i=0; i<SABER_L; i++){
    	
    	for(int k=0; k<SABER_N; k+=P){
    	    memset(res,0,sizeof(res));
    	    
    	    for(int t=0; t<SABER_N; t++)
    	        vprime[t] = 16;
    	        
    	    res[i][0] = 15;
    	    POLVECp2BS(ct, res);
    	    POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
    	    query += 1;
    	    oracle(ct,sk, msg);
    	    
    	    for(int t=k; t<k+P && t<SABER_N; t++){
    		if(msg[t] == 0) vprime[t] = 17, che[i][t][0] = 0;
    		else vprime[t] = 15, che[i][t][0] = 1;
    	    }
    	    
    	    res[i][0] = 15;
    	    POLVECp2BS(ct, res);
    	    POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
    	    query += 1;
    	    oracle(ct,sk, msg);
    	    
    	    for(int t=k; t<k+P && t<SABER_N; t++){
    		if(msg[t] == 0) che[i][t][1] = 0;
    		else che[i][t][1] = 1;
    	    }
    	}
    }
    
    
    for(int i = 0; i < SABER_L; i++) {
        for(int k = 0; k < SABER_N; k++) {
	    if((che[i][k][0] == 0) && (che[i][k][1] == 0)){
     		sk_hat[i][k] = 19;
     	    }
     	    if((che[i][k][0] == 0) && (che[i][k][1] == 1)){
     		sk_hat[i][k] = 1;
     	    }
     	    if((che[i][k][0] == 1) && (che[i][k][1] == 0)){
     		sk_hat[i][k] = 0;
     	    }
     	    if((che[i][k][0] == 1) && (che[i][k][1] == 1)){
     		sk_hat[i][k] = 9;
     	    }
        }   
    }
    
    
    for(int i=0; i<SABER_L; i++){
    	for(int j=0; j<SABER_N; j++){
    	    int cnt = 0;
    	    if(sk_hat[i][j] == 19){
    	        memset(index, 0, sizeof(index));
    	    	for(int k=j+1; k<SABER_N; k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(sk_hat[i][k] == 19){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	vprime[j] = 18;
    	    	for(int k=0; k<cnt; k++)
    	    	    vprime[index[k]] = 18;
    	    	  
    	    	  
    	        memset(res,0,sizeof(res));
    	        res[i][0] = 15;
    	        POLVECp2BS(ct, res);
    	        POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
		query += 1;
    	        oracle(ct,sk, msg);
		
		
    	    	if(msg[j] == 0) sk_hat[i][j] = 3;
    	    	else sk_hat[i][j] = 2;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k=0; k<cnt; k++){
    	    	      if(msg[index[k]] == 0) sk_hat[i][index[k]] = 3;
    	    	      else sk_hat[i][index[k]] = 2;
    	    	    }
    	    	}
    	    }
    	}
    }
    
    
    for(int i=0; i<SABER_L; i++){
    	for(int j=0; j<SABER_N; j++){
    	    int cnt = 0;
    	    if(sk_hat[i][j] == 9){
    	    memset(index, 0, sizeof(index));
    	        memset(index, 0, sizeof(index));
    	    	for(int k=j+1; k<SABER_N; k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(sk_hat[i][k] == 9){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	vprime[j] = 14;
    	    	for(int k=0; k<cnt; k++)
    	    	    vprime[index[k]] = 14;
    	    	  
    	    	  
    	        memset(res,0,sizeof(res));
    	        res[i][0] = 15;
    	        POLVECp2BS(ct, res);
    	        POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
		query += 1;
    	        oracle(ct,sk, msg);
		
		
    	    	if(msg[j] == 0) sk_hat[i][j] = -1;
    	    	else sk_hat[i][j] = 10;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k=0; k<cnt; k++){
    	    	      if(msg[index[k]] == 0) sk_hat[i][index[k]] = -1;
    	    	      else sk_hat[i][index[k]] = 10;
    	    	    }
    	    	}
    	    }
    	}
    }
    
    for(int i=0;i<SABER_L;i++){
    	for(int j=0; j<SABER_N; j++){
    	    int cnt = 0;
    	    if(sk_hat[i][j] == 10){
    	    	memset(index, 0, sizeof(index));
    	    	for(int k=j+1; k<SABER_N; k++){
    	    	    if(cnt + 1 == P)
    	    	        break;
    	    	    if(sk_hat[i][k] == 10){
    	    		index[cnt] = k;
    	    		cnt += 1;
    	    	    }
    	    	}
    	    	
    	    	vprime[j] = 13;
    	    	for(int k = 0; k < cnt; k ++)
    	    	    vprime[index[k]] = 13;
    	    	  
    	    	  
    	        memset(res,0,sizeof(res));
    	        res[i][0] = 15;
    	        POLVECp2BS(ct, res);
    	        POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
		query += 1;
    	        oracle(ct,sk, msg);
		
		
    	    	if(msg[j] == 0) sk_hat[i][j] = -2;
    	    	else sk_hat[i][j] = -3;
    	    	
    	    	if(cnt != 0){
    	    	    for(int k = 0; k < cnt; k ++){
    	    	      if(msg[index[k]] == 0) sk_hat[i][index[k]] = -2;
    	    	      else sk_hat[i][index[k]] = -3;
    	    	    }
    	    	}
    	    }
    	}
    }
    
    
    
   int sum = 0;
   for(int i = 0; i < SABER_L; i ++)
   {
	for(int j = 0; j < SABER_N; j ++)
	{
		//printf("True = sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
        	if(sksv[i][j]!=sk_hat[i][j] && sksv[i][j]-sk_hat[i][j] != 8192)
		{
			printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
			sum ++;
		}
	}
   }
   if(sum != 0){
       printf("Errors = %d \n",sum);
       return 0;
   }
   return query;
}

int main(int argc, char * argv[])
{
    if(argc == 1) {
        printf("Input test times\n");
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

    int count,query=0;
    int pro = rand;
    for(count=0;count<rand;count++)
	{ 
		randombytes(seed, 48);
        	fprintBstr("\nseed = ", seed, 48);
        	randombytes_init(seed, NULL, 256);
		int temp = test_pke_cpa(P);
		printf("Fact query  = %d\n", temp);
		if(temp == 0) pro -= 1;
		query += temp;
	}
    printf("\n\nQuery = %f\n",query*1.0/rand);
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



