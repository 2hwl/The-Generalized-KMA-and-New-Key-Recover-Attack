#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../verify.h"
#include "../pack_unpack.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>


void	fprintBstr(char *S, unsigned char *A, unsigned long long L);
static int test_pke_cpa()
{
    //key mismatch attack on Firesaber
    // parameters: res: b'
    //          vprime: cm
    //            ss_a: message
    //	         query: count the total queries
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];	
    uint8_t ss_a[CRYPTO_BYTES];
    uint16_t res[SABER_L][SABER_N];
    int sk_hat[SABER_L][SABER_N];
    uint16_t vprime[SABER_N];
    uint16_t sksv[SABER_L][SABER_N]; //secret key of the server
    int query=0;
    
    int i,j,k;


    //Generation of secret key sk and public key pk pair
	crypto_kem_keypair(pk, sk);
    BS2POLVECq(sk, sksv); //sksv is the secret-key

    //printf("num = %d %d %d %d %d %d %d\n",num0,num1,num2,num3,num_1,num_2,num_3);
    for(i=0;i<SABER_L;i++){
    	memset(ss_a,0,sizeof(ss_a));
    	ss_a[0] = 1;
    	memset(vprime,0,sizeof(vprime));
    	for(k=0;k<SABER_N;k++){
    		memset(res,0,sizeof(res));
    		if(k == 0){
    			res[i][k] = 140;
    		}
    		else{
    			res[i][SABER_N-k] = -140;
    		}
    		POLVECp2BS(ct, res);
    		vprime[0]=2;
    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
    		if(oracle(ct,sk) == 0){
    			query ++;
			if(k == 0){
	    			res[i][k] = 30;
	    		}
	    		else{
	    			res[i][SABER_N-k] = -30;
	    		}
	    		POLVECp2BS(ct, res);
	    		vprime[0]=12;
	    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			if(oracle(ct,sk) == 0){
				query ++;
				sk_hat[i][k] = 0;			
			}
			else {
				query ++;
				if(k == 0){
		    			res[i][k] = 100;
		    		}
		    		else{
		    			res[i][SABER_N-k] = -100;
		    		}
		    		POLVECp2BS(ct, res);
		    		vprime[0]=14;
		    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
				if(oracle(ct,sk) == 0){
					query ++;
					sk_hat[i][k] = 1;
				}
				else{
					query ++;
					sk_hat[i][k] = 2;				
				}
			}
	    	}
    		else{
    			query ++;
			if(k == 0){
	    			res[i][k] = 120;
	    		}
	    		else{
	    			res[i][SABER_N-k] = -120;
	    		}
	    		POLVECp2BS(ct, res);
	    		vprime[0]=1;
	    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
			if(oracle(ct,sk) == 0){
				query ++;
				sk_hat[i][k] = -1;
			}
			else {
				query ++;
				if(k == 0){
		    			res[i][k] = 100;
		    		}
		    		else{
		    			res[i][SABER_N-k] = -100;
		    		}
		    		POLVECp2BS(ct, res);
		    		vprime[0]=0;
		    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
				if(oracle(ct,sk) == 0){
					query ++;
					sk_hat[i][k] = -2;
				}
				else {
					query ++;
					if(k == 0){
			    			res[i][k] = 80;
			    		}
			    		else{
			    			res[i][SABER_N-k] = -80;
			    		}
			    		POLVECp2BS(ct, res);
			    		vprime[0]=0;
			    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
					if(oracle(ct,sk) == 0){
						query ++;
						sk_hat[i][k] = 3;
					}
					else {
						query ++;
						if(k == 0){
				    			res[i][k] = 130;
				    		}
				    		else{
				    			res[i][SABER_N-k] = -130;
				    		}
				    		POLVECp2BS(ct, res);
				    		vprime[0]=12;
				    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
						if(oracle(ct,sk) == 0){
							query ++;
							sk_hat[i][k] = -3;
						}
						else {
							query ++;
							if(k == 0){
					    			res[i][k] = 10;
					    		}
					    		else{
					    			res[i][SABER_N-k] = -10;
					    		}
					    		POLVECp2BS(ct, res);
					    		vprime[0]=3;
					    		POLT2BS(ct + SABER_POLYVECCOMPRESSEDBYTES, vprime);
							if(oracle(ct,sk) == 0){
								query ++;
								sk_hat[i][k] = 4;
							}
							else {
								query ++;
								sk_hat[i][k] = -4;
							}
						}
					}
				}
			}
    		}
    	}
    }
   int sum = 0;
   for(i=0;i<SABER_L;i++)
   {
	for(j=0;j<SABER_N;j++)
	{
		//printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
        	if(sksv[i][j]!=sk_hat[i][j] && sksv[i][j]-sk_hat[i][j] != 8192)
		{
			printf("sk[%d][%d]:%d sk_hat[%d][%d]:%d\n",i,j,sksv[i][j],i,j,sk_hat[i][j]);
			sum ++;
		}
	}
   }
   if(sum != 0)
   printf("Sum = %d \n",sum);
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
    
    /* random init */
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    for (int i=0; i<48; i++)
	entropy_input[i] = i;
        //entropy_input[i] = rand() % 48;
    randombytes_init(entropy_input, NULL, 256);

    int count,query=0;
    for(count=0;count<rand;count++)
	{ 
		randombytes(seed, 48);
        	fprintBstr("\nseed = ", seed, 48);
        	randombytes_init(seed, NULL, 256);
		int temp = test_pke_cpa();
		printf("Fact query  = %d\n", temp);
		query += temp;
	}
    printf("Query = %f\n",query*1.0/rand);
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

