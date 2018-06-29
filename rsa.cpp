/**
 * Implementation of RSA cryptosystem based on https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29
 * 
 * @author Mamagiannos Dimitrios
 * @date November 2015
 * 
 */

#include "iostream"
#include "fstream"
#include "stdlib.h"
#include "string.h"
#include "ctime"
#include "sys/time.h"
#include "bitset"

#define PRIMES_DATASET_LIMIT 25000

using namespace std;

unsigned long long int choose_prime(unsigned int primePosition,string path){
    
    unsigned long long int prime;
    
    ifstream prime_file;
    prime_file.open(path.c_str(),ios::in);
    
    if(prime_file.is_open()){
        
        unsigned int i=0;
        
        while(!prime_file.eof()){
	  prime_file >> prime;
	  if (i==primePosition) break;
	  i++;
        }
    }
    return prime;
    
}

/**
 * Calculate greatest common divisor for two numbers a,b
 *
 */
unsigned long long int gcd(unsigned long long int a,unsigned long long int b){
    
    unsigned long long int r = a%b;
    
    while (b != 0){
        r=b;
        b=a%r;
        a=r;
    }
    return a;
    
}

/**
 * Calculate e. It is necessary e and euler_function to be coprime numbers.
 */
unsigned long long int calculate_e(unsigned long long int euler_function){
    
    unsigned long long int e;
    do{
        e = rand()%(euler_function) + 1; //1 < e < euler_function
    }while (gcd(e,euler_function)!=1);
    
    
    return e;
    
}


/**
 * Implementation of extended Euclidean method.
 * If a and b are integers then there are x,y such as a*x +b*y = gcd(a,b)
 */
pair<unsigned long long int, pair<unsigned long long int, unsigned long long int> > extendedEuclid(unsigned long long a, unsigned long long b) {
    if(a == 0) return make_pair(b, make_pair(0, 1));
    pair<unsigned long long int, pair<unsigned long long int, unsigned long long int> > p;
    p = extendedEuclid(b % a, a);
    return make_pair(p.first, make_pair(p.second.second - p.second.first*(b/a), p.second.first));
}


/**
 * Compute inverse modulo x = a^-1 of two integers a,m.
 * (a*x) mod m =1 
 * If a and b are integers then there are x,y such as a*x +b*y = gcd(a,b)
 */
int modInverse(unsigned long long a, unsigned long long int m) {
    return (extendedEuclid(a,m).second.first + m) % m;
}


/**
 * Compute (A^B) mod N based on Fermat's little theorem
 * https://en.wikipedia.org/wiki/Fermat's_little_theorem 
 */
unsigned long long int ApowBmodN(unsigned long long int a, unsigned long long int b,unsigned long long int MOD){
    
    unsigned long long int x=1,y=a;
    
    while(b>0){
        if(b%2 == 1){
	  x=(x*y);
	  if(x>MOD) x%=MOD;
        }
        y= (y*y);
        if (y>MOD) y%=MOD;
        b /= 2;
    }
    return x;
    
}

/**
 * Main 
 */
void RSA_process(unsigned long long int *n,unsigned long long int *e,unsigned long long int *d,unsigned long long int *euler_function){
    
    
    
    unsigned long long int p,q;
    
    //Choose randomly p,q from prime number dataset
    
    p=choose_prime(rand()%(2*PRIMES_DATASET_LIMIT),"primes_dataset.txt");
    
    q=choose_prime(rand()%PRIMES_DATASET_LIMIT,"primes_dataset.txt"); 
    
    *n=p*q;
    
    *euler_function = *n -p -q +1 ;
    
    *e = calculate_e(*euler_function) ;
    
    *d = modInverse(*e,*euler_function);
    
    
    if( ( (*e) * (*d) ) % (*euler_function) != 1){
        //perror("\nERROR : d is calculated wrong\n");
        RSA_process(n,e,d,euler_function);
        
        int test_num = 5,test_ENC,test_DEC;
        
        test_ENC = ApowBmodN(test_num,*e,*n); 
        
        test_DEC = ApowBmodN(test_ENC,*d,*n);
        
        if (test_DEC != test_num) RSA_process(n,e,d,euler_function);
        
    };
    
}

/**
 * Main
 */

int main(){
    
    srand(time(NULL));
    
    struct timeval start,end;
    
    unsigned long long int n,e,d,euler_function;
    
    gettimeofday(&start, NULL);
    
    RSA_process(&n,&e,&d,&euler_function);
    
    gettimeofday(&end, NULL);
    
    cout<<"Total duration of RSA private & public key distribution  is "
    <<(double)((end.tv_usec - start.tv_usec)/1.0e6 + end.tv_sec - start.tv_sec)<<" sec\n";
    
    cout<<"n = "<<n<<"\n";
    
    cout<<"e = "<<e<<"\n";   
    cout<<"d = "<<d<<"\n";
    cout<<"Euler function f is "<<euler_function<<"\n";
    cout<<"GCD between e & euler_function is "<<gcd(e,euler_function)<<"\n";
    cout<<"(e*d) mod euler_function = " << (e*d)%euler_function <<"\n";
    cout<<"binary <32bit> n = "<< std::bitset<32>(n)<<"\n";
    cout<<"binary <32bit> d = "<< std::bitset<32>(d)<<"\n";
    
    
    string str ;
    
    cout<<"Insert message to encrypt:\n";
    cin>>str;
    
    int size=str.size();
    char buffer[1024];
    
    strcpy(buffer,str.c_str());
    cout<<"Message is :";
    for(int i=0;i<size;i++){
        cout<<buffer[i];
    }
    cout<<"\n";
    
    unsigned long int enc[1024];
    
    for (int i=0;i<size;i++){    
        enc[i] =ApowBmodN(buffer[i],e,n); 
    }
    
    cout<<"Encrypted message is :";
    for(int i=0;i<size;i++){
        char m = enc[i]; 
        cout<<m;
    }
    cout<<"\n";
    
    unsigned long int dec[1024];
    
    for (int i=0;i<size;i++){
        dec[i] = ApowBmodN(enc[i],d,n);
    }
    
    cout<<"Decrypted message is :";
    for(int i=0;i<size;i++){
        char m = dec[i]; 
        cout<<m;
    }
    cout<<"\n";
    
    return 0;
}

