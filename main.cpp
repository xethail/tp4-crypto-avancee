#include <iostream>
#include <string>
using namespace std;


static const uint8_t S[16]={ 
  0x3, 0xE, 0x1, 0xA, 0x4, 0x9, 0x5, 0x6, 0x8, 0xB, 0xF, 0x2, 0xD, 0xC, 0x0, 0x7
};

static const uint8_t S_inv[16]={
  0xE, 0x2, 0xB, 0x0, 0x4, 0x6, 0x7, 0xF, 0x8, 0x5, 0x3, 0x9, 0xD, 0xC, 0x1, 0xA
};

/* Cipher to cryptanalyse */
class Cipher
{
private :
  uint8_t k0;
  uint8_t k1;

  /*  Boite S et son inverse */
  const uint8_t S [16]={ 
    0x3, 0xE, 0x1, 0xA, 0x4, 0x9, 0x5, 0x6, 0x8, 0xB, 0xF, 0x2, 0xD, 0xC, 0x0, 0x7
  };

  const uint8_t S_inv [16]={
    0xE, 0x2, 0xB, 0x0, 0x4, 0x6, 0x7, 0xF, 0x8, 0x5, 0x3, 0x9, 0xD, 0xC, 0x1, 0xA
  };

  uint8_t roundFunc(uint8_t input)
  {
    // TODO
    return 0;
  }

  uint8_t roundFunc_inv(uint8_t input)
  {
    // TODO
    return 1;
  }

public :
  Cipher()
  {   
    k0 = rand() % 16;                  //Create random subkey0
    k1 = rand() % 16;                  //Create random subkey1
    
    printf(" First sub-key k0 = %x\n", k0);
    printf(" Second sub-key k1 = %x\n\n", k1);
  }

  Cipher(uint8_t key0, uint8_t key1)
  {   
    k0 = key0;
    k1 = key1;
  }

  uint8_t encrypt(uint8_t input)
  {
    // TODO
    return 0;
  }

  uint8_t decrypt(uint8_t input)
  {
    // TODO
    return 0;        
  }
};


class Cryptanalysis
{
private:
  // Vector to store the plaintexts and cipertexts 
  // Plaintexts
  uint8_t knownP0[1000];
  uint8_t knownP1[1000];

  // Ciphertexts
  uint8_t knownC0[1000];
  uint8_t knownC1[1000];


  uint8_t goodP0, goodP1, goodC0, goodC1;

  int chardatmax;
  int chardat0[16];


public :
  Cryptanalysis(){
    chardatmax = 0;
  }

  /* Difference Distribution Table of the S-boxe */
  void findBestDiffs(void){
    uint8_t i,j;
    uint8_t X,Xp,Y,Yp,DX,DY; 
    uint8_t T[16][16]; // Tableau pour comptabiliser les occurrences
    for (i=0;i<16;++i){
      for (j=0;j<16;++j){
	      T[i][j]=0;
      }
    }

    printf("\n Creating XOR differential table:\n");
      
    /* Question 1 : compléter le code afin d'afficher la matrice T des différences */
    // TODO

    /* Affichage des différences dans un tableau */
    for (i=0;i<16;++i){
      printf("[");
      for (j=0;j<16;++j){
      	printf(" %u ",T[i][j]);
      }
      printf("]\n");
    }

    printf("\n Displaying most probable differentials:\n");

    /* TODO */
    /* Identifier les différentielles apparaissant avec plus forte probabilité */
    /* Elles seront exploitées dans la suite de l'attaque */
  }

  void genCharData(int diffIn, int diffOut)
  {
    printf("\n Generating possible intermediate values based on differential (%x --> %x):\n", diffIn, diffOut);

    // TODO
  }

  void genPairs(Cipher cipher ,uint8_t diffIn, int nbPairs)
  {
    printf("\n Generating %i known pairs with input differential of %x.\n", nbPairs, diffIn);

    /* Question 2 : compléter le code afin de produire des paires de chiffrés avec la bonne différence */

    // TODO
  }

  void findGoodPair(int diffOut, int nbPairs)
  {
    printf("\n Searching for good pair:\n");
    
    /* Question 4 : compléter le code afin de produire une paire avec la bonne caractéristique en se basant sur le chiffrement */

    // TODO
    if(true)
    printf(" No good pair found!\n");
  }

  int testKey(int testK0, int testK1, int nbPairs)
  {
    // TODO
  }

  void crack(int nbPairs)
  {
    printf("\nBrute forcing reduced keyspace:\n");

    // TODO
  }
};


//////////////////////////////////////////////////////////////////
//                             MAIN                             //
//////////////////////////////////////////////////////////////////

int main()
{
  
  srand(time(NULL));                                                      //Randomize values per run
  Cipher cipher;
  uint8_t message = rand() % 16;
  printf(" Producing a random message : %x\n", message);
  uint8_t ciphertext = cipher.encrypt(message);
  printf(" Encrypted message : %x\n", ciphertext);
  uint8_t plaintext = cipher.decrypt(ciphertext);
  printf(" Decrypted message : %x\n", plaintext);

  if(message == plaintext) 	printf(" --> Success\n");
  else 						printf(" --> Failure\n");

      
  int nbPairs = 0;                                                                //Define number of known pairs (note that 16 is a brut force)
  uint8_t diffIn = 0;
  uint8_t diffOut = 0;
    

  // Cryptanalysis cryptanalysis;
  // cryptanalysis.findBestDiffs();                                                                //Find some good differentials in the S-Boxes
  // cryptanalysis.genCharData(diffIn, diffOut);                                                          //Find inputs that lead a certain characteristic
  // cryptanalysis.genPairs(cipher, diffIn, nbPairs);                                                                //Generate chosen-plaintext pairs
  // cryptanalysis.findGoodPair(diffOut,nbPairs);                                                            //Choose a known pair that satisfies the characteristic
  // cryptanalysis.crack(nbPairs);                                                                    //Use charData and "good pair" in find key                                                               

  return 0;    
}
