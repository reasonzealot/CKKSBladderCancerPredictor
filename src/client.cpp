#include "client.h"
#include "helper.h"
#include <iostream>
#include <fstream>
#include <cstdio>
#include <string>
#define SCALE pow(2.0, 40)
using namespace std;
using namespace seal;


void client_key_gen()
{

    EncryptionParameters parms(scheme_type::ckks);
    // TODO: poly_modulus_degree should be set by users
    // TODO: the array {60, 40, ..., 60 } should be set by users
    //! security paramter would be at least 128 according to
    //!  [1] Albrecht et al., Homomorphic Encryption Standard, https://eprint.iacr.org/2019/939.pdf
    // size_t poly_modulus_degree = 32768;
    // parms.set_poly_modulus_degree(poly_modulus_degree);
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree,
    //                          { 60, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    //                            40, 40, 40, 40, 40, 40, 40, 40, 40, 60 }));

    // size_t poly_modulus_degree = 16384;
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 40, 40, 40, 40, 40, 60}));
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 60}));

    SEALContext context(parms);

    print_parameters(context);

    KeyGenerator keygen(context);

    SecretKey secret_key = keygen.secret_key();

    Serializable<PublicKey> public_key = keygen.create_public_key();

    Serializable<RelinKeys> relin_keys = keygen.create_relin_keys();

    Serializable<GaloisKeys> galois_keys = keygen.create_galois_keys();
    //! end of parameter setting for ckks


    // saving ckks parameters, secret key, public key, relinearization key, and galois key ...

    ofstream parms_stream("../client/fhe_setup/parameters", ios::binary);


    ofstream sk_stream("../client/fhe_setup/secret_key", ios::binary);


    ofstream pk_stream("../client/fhe_setup/public_key", ios::binary);


    ofstream rlk_stream("../client/fhe_setup/relin_key", ios::binary);


    ofstream gk_stream("../client/fhe_setup/galois_key", ios::binary);

	parms.save(parms_stream);
	parms_stream.close();
	
	secret_key.save(sk_stream);
    sk_stream.close();
    	
	public_key.save(pk_stream);
	pk_stream.close();
	
    relin_keys.save(rlk_stream);
    rlk_stream.close();
    	
    galois_keys.save(gk_stream);
    gk_stream.close();

}



void client_encrypt_data(string &data_dir)
{

    vector<double> x;
    string patient_data = data_dir;
    read_one_column(x, patient_data);
    x.push_back(1.0);

    size_t num_sample = 1; // for the moment, the number of sample to be tested is only one.
    
    // load parameters and keys
    
    ifstream parms_stream("../client/fhe_setup/parameters", ios::binary);
    ifstream pk_stream("../client/fhe_setup/public_key", ios::binary);
    
    EncryptionParameters parms;
    parms.load(parms_stream);
    
    SEALContext context(parms);

    PublicKey public_key;
    public_key.load(context, pk_stream);
    

    parms_stream.seekg(0, parms_stream.beg);
    pk_stream.seekg(0, pk_stream.beg);
    parms_stream.close();
    pk_stream.close();

    double scale = SCALE;
    CKKSEncoder encoder(context);
    Encryptor encryptor(context, public_key);


    for (size_t i = 0; i < num_sample; i++)
    {
        //cout<<"encrypted data ofstream"<<endl;
        string patient_enc_data_out = "../client/encrypted_data/bladder_cancer_patient_0001_encrypted";
        ofstream enc_data_stream(patient_enc_data_out, ios::binary);
        //cout<<"data out"<<endl;

        vector<Ciphertext> x_encrypted;
        vector<double> x_tmp = x;
        encode_encrypt(encoder, encryptor, x_tmp, scale, x_encrypted);
        size_t num_sect = x_encrypted.size();
	    // cout<<"num_sect = "<<num_sect<<endl;

        for (size_t k = 0; k < num_sect; k++)
        {
            x_encrypted[k].save(enc_data_stream);
        }
        enc_data_stream.close();
    }
}

void client_decrypt_result(string &result_dir)
{

    // cout.precision(10);
    // cout << fixed;

    ifstream parms_stream("../client/fhe_setup/parameters", ios::binary);
    ifstream sk_stream("../client/fhe_setup/secret_key", ios::binary);


    EncryptionParameters parms;
    parms.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);
    parms_stream.close();

    SEALContext context(parms);
    CKKSEncoder encoder(context);

    SecretKey secret_key;
    secret_key.load(context, sk_stream);
    sk_stream.seekg(0, parms_stream.beg);
    sk_stream.close();

    Decryptor decryptor(context, secret_key);


    string patient_enc_result = result_dir;
    ifstream enc_result_stream(patient_enc_result, ios::binary);
    
    Ciphertext ctx;
    ctx.load(context, enc_result_stream);
    enc_result_stream.seekg(0, enc_result_stream.beg);
    enc_result_stream.close();
    
    vector<double> y_decrypted;
    decrypt_decode(encoder,decryptor,ctx,y_decrypted);
    cout << "   + Client: the result after decryption: " << y_decrypted[0] << endl;
    
}
