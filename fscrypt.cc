/*
 * fscrypt.cc
 *
 *  Created on: 25-Sep-2019
 *      Author: tod
 */

#include"fscrypt.h"
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);		
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);
unsigned char iv[]="00000000";
int i,count=0,pad,reslen,size;
unsigned char *unit,*ures,*punit,*res;
BF_KEY *key_str; 

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)			//fs_encrypt() to encrypt plainttext from main.cc
{
	size=bufsize;										//initialize parameters from function call
	key_str=(BF_KEY *)malloc(sizeof(BF_KEY)); 
	unsigned char *pt=(unsigned char *)plaintext;
	unit=(unsigned char *)malloc(sizeof(unsigned char)*BLOCKSIZE);				//allocating memory
	res=(unsigned char *)malloc(sizeof(unsigned char)*(bufsize));
	ures=(unsigned char *)malloc(sizeof(unsigned char)*BLOCKSIZE);
	BF_set_key(key_str, strlen(keystr),(const unsigned char *)keystr);			//call BF_set_key() to setup key using len bytes long key at data
	if(bufsize % BLOCKSIZE==0)								//checking buffersize with BLOCKSIZE for encryption 
		reslen=bufsize;
	else
		reslen=bufsize+(bufsize % BLOCKSIZE);		
	i=0;
	do
	{
		res[i]='0';							
		i++;
	}while(i<bufsize);
	i=0;
	do
	{
		ures[i]='0';
		unit[i]=iv[i];
		i++;
	}while(i<BLOCKSIZE);
	do
	{
		for(i=0;i<BLOCKSIZE;i++)
			unit[i]=unit[i]^(unsigned char)(pt[bufsize-size+i]);			//XOR each byte in unit[] until size is >= BLOCKSIZE
		BF_ecb_encrypt(unit,ures,key_str,BF_ENCRYPT);					//call BF_ecb_encrypt()
		for(i=0;i<BLOCKSIZE;i++)
		{
			unit[i]=ures[i];
			res[bufsize-size+i]=ures[i];
		}
		size=size-BLOCKSIZE;
	}while(size >= BLOCKSIZE);
	pad=BLOCKSIZE-size;									//assigning pad size
	*resultlen=bufsize-size;
	if(size>0)
	{
		i=0;
		do
		{
			if(size==0)
			{
				unit[i]=unit[i]^(unsigned char)(pad & 0xFF);			//logical AND with 0xFF	
			}
			else
			{
				unit[i]=unit[i]^(unsigned char)pt[bufsize-size];
				size --;	
			}
			i++;	
		}while(i<BLOCKSIZE);
		BF_ecb_encrypt(unit,ures,key_str,BF_ENCRYPT);					//call BF_ecb_encrypt() to encrypt
		for(i=0;i<BLOCKSIZE;i++)
		{
			res[bufsize-BLOCKSIZE+pad+i]=ures[i];
		}
		*resultlen+=BLOCKSIZE;
	}
	free(ures);										//free all allocated variables
	free(key_str);
	free(unit);
	return (void *) res;									//return encrypted result
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)			//fs_decrypt() to decrypt
{
	size = bufsize;										//initialize parameters from function call
	unsigned char *ct=(unsigned char *)ciphertext;
	key_str=(BF_KEY *)malloc(sizeof(BF_KEY));
	BF_set_key(key_str, strlen(keystr),(const unsigned char *)keystr);			//call BF_set_key() to setup key using len bytes long key at data
	punit=(unsigned char *)malloc(sizeof(unsigned char)*BLOCKSIZE);				//allocating memory
	unit=(unsigned char *)malloc(sizeof(unsigned char)*BLOCKSIZE);
	res=(unsigned char *)malloc(sizeof(unsigned char)*(bufsize));
	ures=(unsigned char *)malloc(sizeof(unsigned char)*BLOCKSIZE);
	i=0;
	do											//initializing required variables 
	{
		res[i]='0';						
		punit[i]=iv[i];
		ures[i]='0';
		unit[i]='0';
		i++;	
	}while(i<bufsize || i<BLOCKSIZE);
	do
	{
		for(i=0;i<BLOCKSIZE;i++)
		{
			unit[i]=(unsigned char)ct[bufsize-size+i];			
		}
		BF_ecb_encrypt(unit,ures,key_str,BF_DECRYPT);					//call BF_ecb_encrypt() to decrypt the plaintext
		for(i=0;i<BLOCKSIZE;i++)
		{
			ures[i]=ures[i]^punit[i];						//XOR puint with result until size >= BLOCKSIZE
			res[bufsize-size+i]=ures[i];
			punit[i]=unit[i];
		}		
		size =size-BLOCKSIZE;
	}while(size >= BLOCKSIZE);
	for(i=bufsize-1;i>bufsize-BLOCKSIZE+1;i--)
	{
		if(res[bufsize-1]!=res[i-1])
			break;
		else
			count ++;
	}
	if((count+1)>=(int)(res[bufsize-1]))
		*resultlen=bufsize-(int)(res[bufsize-1]);
	else
		return NULL;
	free(punit);										//free all allocated variables
	free(key_str);
	free(ures);
	free(unit);
	return (void *)res;									//return decrypted cipher text
}
