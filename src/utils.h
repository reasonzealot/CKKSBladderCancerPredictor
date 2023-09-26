#include"seal/seal.h"
#include<iomanip>
using namespace std;
using namespace seal;

// split x into num sections, each section is of the same length, 
// except the last section may be with less elements than previous ones
void split(vector<double> &x, size_t num, vector<vector<double>> &x_data);

void encode_encrypt(CKKSEncoder &encoder, Encryptor &encryptor, vector<double> &x, 
                        double scale, vector<Ciphertext> &x_encrypted);

void encode_encrypt(CKKSEncoder &encoder, Encryptor &encryptor, double x, 
                        double scale, Ciphertext &x_encrypted);

void decrypt_decode(CKKSEncoder &encoder, Decryptor &decryptor, Ciphertext &x_encrypted, vector<double> &x);

// This total_sum works only for CKKS
void total_sum_inplace(Evaluator &evaluator, GaloisKeys &galois_keys, 
                                size_t slot_count, Ciphertext & y_encrypted);

void linear_eval(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys,
                        vector<Ciphertext> &w_encrypted, vector<Ciphertext> &x_encrypted, 
                        size_t slot_count, Ciphertext &y_encrypted, vector<int> &none_zero);


void plain_encrypted_vector_inner_product(Evaluator &evaluator, CKKSEncoder &encoder, double scale, RelinKeys &relin_keys, GaloisKeys &galois_keys,
                        vector<vector<double>> &w, vector<Ciphertext> &x_encrypted, 
                        size_t slot_count, Ciphertext &y_encrypted,vector<int> &none_zero);


void poly_eval_inplace(Evaluator &evaluator, RelinKeys &relin_keys, 
                        vector<Ciphertext> &g_encrypted, Ciphertext &x_encrypted);

void poly_eval_inplace_test(Evaluator &evaluator, RelinKeys &relin_keys, 
                        vector<Ciphertext> &g_encrypted, Ciphertext &x_encrypted);

// evaluate linear function in plaintext
double linear_eval_plain(vector<double> &w, vector<double> &x,  double b);

double inner_product(vector<double> &w, vector<double> &x);

long int memory_usage();

void remove_files(int submission);

void read_one_column(vector<double> &M, string &file_name);
