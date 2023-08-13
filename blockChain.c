// SHA256(source,size,Destination) -->> source and Destination are type of "unsigned char* -->> Also it return "unsigned char* "

//SHA256_DIGEST_LENGTH - this constant is declared in crypto.h

/* SHA-256 treats input data as a
* contiguous array of 32 bit
* wide big-endian values. */

#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include "openssl/crypto.h"
#include "openssl/sha.h"


struct block{
    unsigned char hash_prevBlock[SHA256_DIGEST_LENGTH];   //unsigned char array
    int block_Data;
    struct block *next_Block;
};

void addBlock(int input_Data);
void verify_Chain();
void tamper_Data(int n,int new_Data);
void hack_Chain();
unsigned char* toString(struct block b);
void hash_Printer(unsigned char hash[],int length);
int hash_Compare(unsigned char *str1,unsigned char *str2);
void print_Block(struct block *b);
void print_All_Blocks();

struct block *head = NULL;

void addBlock(int input_Data){
    //For first input block
    if(head==NULL){
        struct block *new_Block = (struct block*)malloc(sizeof(struct block));
        head = new_Block;
        SHA256("",sizeof(""),head->hash_prevBlock);
        head->block_Data = input_Data;
        return;
    }
    //If block or blocks are already present
    struct block *temp = head;
    while(temp->next_Block != NULL){
        temp = temp->next_Block;
    }

    struct block *new_Block = (struct block*)malloc(sizeof(struct block)); //Creating a new BLock
    new_Block->block_Data = input_Data;
    temp->next_Block = new_Block;
    SHA256(toString(*temp),sizeof(*temp),new_Block->hash_prevBlock);
}

void verify_Chain(){

    if(head == NULL){
        printf("BlockChain is Empty !");
        return;
    }

    struct block *current_Block = head->next_Block;
    struct block *previous_Block = head;
    int count = 1;
    while(current_Block!=NULL){
        printf("%d\t[%d]\t",count++,current_Block->block_Data);
        hash_Printer(SHA256(toString(*previous_Block),sizeof(*previous_Block),NULL),SHA224_DIGEST_LENGTH);   //Calculating <hash> of previous block
        printf(" - ");
        hash_Printer(current_Block->hash_prevBlock,SHA256_DIGEST_LENGTH); //Getting <hash> of previous block (Which is stored in current block's prev_Hash char array)
        if(hash_Compare(SHA256(toString(*previous_Block),sizeof(*previous_Block),NULL),current_Block->hash_prevBlock)){
            printf("\nVerified\n");
        }
        else printf("Verification Falied !! Data is tampered !!\n");
        previous_Block = current_Block;
        current_Block = current_Block->next_Block;
    }
}

//Function to Tamper the data
void tamper_Data(int n,int new_Data){
    struct block *current_Block = head;
    int count = 0;
    if(current_Block==NULL){
        printf("Nth block doesn't exist !");
        return;
    }
    while(count!=n){
        if(current_Block->next_Block == NULL && count!=n){
            printf("Nth block doesn't exist !");;
            return;
        }
        else if(count==n){
            break;
        }
        current_Block = current_Block->next_Block;
        count++;
    }
    printf("Before tampering : \n");
    print_Block(current_Block);

    current_Block->block_Data = new_Data;

    printf("After tampering : \n");
    print_Block(current_Block);
    printf("\n");
}

void hack_Chain(){
    struct block *current_Block = head;
    struct block *previous_Block;
    if(current_Block==NULL){
        printf("BlockChain is Empty !");
        return;
    }
    while(1){
        previous_Block = current_Block;
        current_Block = current_Block->next_Block;
        if(current_Block==NULL){
            return;
        }
        if(!hash_Compare(SHA256(toString(*previous_Block),sizeof(*previous_Block),NULL),current_Block->hash_prevBlock)){
            hash_Printer(
                SHA256(toString(*previous_Block),sizeof(*previous_Block),current_Block->hash_prevBlock),SHA256_DIGEST_LENGTH
            );
            printf("\n");
        }
    }
}

unsigned char* toString(struct block b){
    unsigned char *str = malloc(sizeof(unsigned char)*sizeof(b));
    memcpy(str,&b,sizeof(b));
    return str;
}

void hash_Printer(unsigned char hash[],int length){
    for(int i=0;i<length;i++){
        printf("%02x",hash[i]);
    }
}

int hash_Compare(unsigned char *str1,unsigned char *str2){
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        if(str1[i]!=str2[i]){
            return 0;
        }
    }
    return 1;
}

void print_Block(struct block *b){
    printf("%p]t",b);
    hash_Printer(b->hash_prevBlock,sizeof(b->hash_prevBlock));
    printf("\t[%d]\t",b->block_Data);
    printf("%p\n",b->next_Block);
}

void print_All_Blocks(){
    struct block *current_Block = head;
    int count = 0;
    while(current_Block){
        print_Block(current_Block);
        current_Block = current_Block->next_Block;
    }
}

int main(){
    int choice,data,n,pos;
    printf("1).Add Block\n2).Add n random Block\n3).Alter nth Block\n4).Print All Blocks\n5).Verify Chain\n6).Hack Chain\n7).Exit\n");
    while(1){
        printf("Select : ");
        scanf("%d",&choice);
        switch(choice){
            case 1:
                printf("Enter the data : ");
                scanf("%d",&data);
                addBlock(data);
                break;
            case 2:
                printf("Howmany blocks you want to enter : ");
                scanf("%d",&n);
                for(int i=0;i<n;i++){
                    int r = rand()%(n*10);
                    addBlock(r);
                    printf("Entered : %d",r);
                    printf("\n");
                }
                break;
            case 3:
                printf("Enter the block's position : ");
                scanf("%d",&pos);
                printf("Enter the value : ");
                scanf("%d",&data);
                tamper_Data(pos,data);
                break;
            case 4:
                print_All_Blocks();
                break;
            case 5:
                verify_Chain();
                break;
            case 6:
                hack_Chain();
                break;
            case 7:
                return 0;
                break;
            default : 
                printf("Wrong Choice : ");
                break;
        }
    }
}