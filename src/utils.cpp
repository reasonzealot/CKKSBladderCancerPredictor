#include "utils.h"
#include "helper.h"
#include <iostream>
#include <fstream>
#include <sys/resource.h>
#define SCALE pow(2.0, 40)

using namespace std;


void read_one_column(vector<double> &M, string &file_name)
{
    fstream in_file(file_name);
    if (!in_file.is_open())
    {
        cout << "open " << file_name <<  " fail!" << endl;
        return;
    }

    string line;
    M.clear();

    while (getline(in_file, line))
    {
        // cout << line << endl;
        M.push_back(stod(line)); // stod for string to double
        
    }

    in_file.close();
}


void split(vector<double> &x, size_t num, vector<vector<double>> &x_data)
{
    size_t d = ceil((double)x.size() / (double)num);
    size_t n = x.size();
    if (n / d + 1 < num)
    {
        x_data.resize(n / d + 1);
    }
    else
    {
        x_data.resize(num);
    }
    if (d == 1)
    {
        x_data.resize(n);
    }
    size_t dim = x_data.size();
    // cout << "   d:" << d << endl;
    // cout << "   n/d+1:" << n/d + 1 << endl;
    // cout << "   size of data is:" << dim << endl;
    for (size_t i = 0; i < dim - 1; i++)
    {
        x_data[i].clear();
        for (size_t j = 0; j < d; j++)
        {
            x_data[i].push_back(x[i * d + j]);
        }
    }
    x_data[dim - 1].clear();
    for (size_t i = d * (dim - 1); i < n; i++)
    {
        x_data[dim - 1].push_back(x[i]);
    }
}

void encode_encrypt(CKKSEncoder &encoder, Encryptor &encryptor, vector<double> &x,
                    double scale, vector<Ciphertext> &x_encrypted)
{
    size_t slot_count = encoder.slot_count();
    size_t dim = x.size();
    if (dim < slot_count)
    {
        Plaintext x_plain;
        encoder.encode(x, scale, x_plain);
        x_encrypted.resize(1);
        encryptor.encrypt(x_plain, x_encrypted[0]);
    }
    else
    { // split x into num_sect sections, each section forms a new vector
        size_t num_sect = ceil((double)dim / (double)slot_count);
        vector<vector<double>> x_data;
        split(x, num_sect, x_data);
        x_encrypted.resize(num_sect);
        for (size_t i = 0; i < num_sect; i++)
        {
            Plaintext x_plain;
            encoder.encode(x_data[i], scale, x_plain);
            // cout << "encode_encrypt: x_data[" << i << "]:" << endl;
            // print_vector(x_data[i]);
            encryptor.encrypt(x_plain, x_encrypted[i]);
        }
    }
}

void encode_encrypt(CKKSEncoder &encoder, Encryptor &encryptor, double x, double scale, Ciphertext &x_encrypted)
{
    vector<double> v;
    for (size_t i = 0; i < encoder.slot_count(); i++)
    {
        v.push_back(x);
    }
    Plaintext x_plain;
    encoder.encode(v, scale, x_plain);
    encryptor.encrypt(x_plain, x_encrypted);
}

void decrypt_decode(CKKSEncoder &encoder, Decryptor &decryptor, Ciphertext &x_encrypted, vector<double> &x)
{
    Plaintext x_decrypted;
    decryptor.decrypt(x_encrypted, x_decrypted);
    encoder.decode(x_decrypted, x);
}

void total_sum_inplace(Evaluator &evaluator, GaloisKeys &galois_keys,
                       size_t slot_count, Ciphertext &y_encrypted)
{
    Ciphertext tmp_encrypted;
    for (int i = 0; i < (int)(log(slot_count) / log(2)); i++)
    {
        evaluator.rotate_vector(y_encrypted, pow(2, i), galois_keys, tmp_encrypted);
        evaluator.add_inplace(y_encrypted, tmp_encrypted);
    }
}


void plain_encrypted_vector_inner_product(Evaluator &evaluator, CKKSEncoder &encoder, double scale, RelinKeys &relin_keys, GaloisKeys &galois_keys,
                        vector<vector<double>> &w, vector<Ciphertext> &x_encrypted, 
                        size_t slot_count, Ciphertext &y_encrypted,vector<int> &none_zero)
{
    auto num_sect = x_encrypted.size();
    if (num_sect != w.size())
    {
        cerr << "plain_encrypted_vector_inner_product: the number of sections of w does not match with that of x" << endl;
    }
    // cout << "   + num_sect = " << num_sect << endl;
    vector<Ciphertext> total_sum_encrypted;
    vector<Plaintext> plain_w;

    for (size_t i = 0; i < num_sect; i++)
    {
        Plaintext plain_tmp;
        encoder.encode(w[i], scale, plain_tmp);
        plain_w.push_back(plain_tmp);
    }

    for (size_t i = 0; i < num_sect; i++)
    {
        Ciphertext tmp_encrypted;
        if (none_zero[i] == 0||i == num_sect-1)
        {
            evaluator.multiply_plain(x_encrypted[i], plain_w[i], tmp_encrypted);
            // cout<<"multiply_plain done"<<" and i = "<<i<<endl;
            evaluator.rescale_to_next_inplace(tmp_encrypted);
            total_sum_inplace(evaluator, galois_keys, slot_count, tmp_encrypted);
            // cout << "    + size of total_sum_encrypted[" << i << "]: " << total_sum_encrypted[i].size() << endl;
            // cout << "    + Exact scale of total_sum_encrypted[" << i << "]: "  << total_sum_encrypted[i].scale() << endl;
            tmp_encrypted.scale() = SCALE;
            total_sum_encrypted.push_back(tmp_encrypted);
            // cout<<"total sum done"<<endl;
        }
    }
    evaluator.add_many(total_sum_encrypted, y_encrypted);
}

void linear_eval(Evaluator &evaluator, RelinKeys &relin_keys, GaloisKeys &galois_keys,
                 vector<Ciphertext> &w_encrypted, vector<Ciphertext> &x_encrypted,
                 size_t slot_count, Ciphertext &y_encrypted)
{
    size_t num_sect = w_encrypted.size();
    if (num_sect != x_encrypted.size())
    {
        cerr << "linear_function_eval: the number of sections of w does not match with that of x" << endl;
    }
    vector<Ciphertext> total_sum_encrypted(num_sect);
    for (size_t i = 0; i < num_sect; i++)
    {
        // Ciphertext tmp_encrypted;
        evaluator.multiply(w_encrypted[i], x_encrypted[i], total_sum_encrypted[i]);
        evaluator.relinearize_inplace(total_sum_encrypted[i], relin_keys);
        evaluator.rescale_to_next_inplace(total_sum_encrypted[i]);
        total_sum_inplace(evaluator, galois_keys, slot_count, total_sum_encrypted[i]);
        // cout << "    + size of total_sum_encrypted[" << i << "]: " << total_sum_encrypted[i].size() << endl;
        // cout << "    + Exact scale of total_sum_encrypted[" << i << "]: "  << total_sum_encrypted[i].scale() << endl;
        // total_sum_encrypted[i].scale() = pow(2.0, 40);
    }
    evaluator.add_many(total_sum_encrypted, y_encrypted);
}


double linear_eval_plain(vector<double> &w, vector<double> &x, double b)
{
    double y = b;
    if (w.size() == x.size())
    {
        for (size_t i = 0; i < x.size(); i++)
        {
            y += w[i] * x[i];
        }
        cout<<"y = "<<y<<endl;
        return y;
    }
    else
    {
        cout << "linear_eval_plain:  "
             << "the dimension of w and x do not match" << endl;
        return 0.0;
    }
}



double inner_product(vector<double> &w, vector<double> &x)
{
    double y = 0;
    if (w.size() == x.size())
    {
        for (size_t i = 0; i < x.size(); i++)
        {
            y += w[i] * x[i];
        }
        return y;
    }
    else
    {
        cout << "linear_eval_plain:  "
             << "the dimension of w and x do not match" << endl;
        return 0.0;
    }
}



long int memory_usage()
{
    struct rusage usage;

    if (!getrusage(RUSAGE_SELF, &usage))
    {
#ifndef __APPLE__
        return usage.ru_maxrss * 1000;
#else
        return usage.ru_maxrss;
#endif
    }
    else
    {
        return -1;
    }
}



