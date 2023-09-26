#include "server.h"
#include "helper.h"
#include "utils.h"
#define SCALE pow(2.0, 40)

void server_evaluation(string &model_dir)
{

    // load parameters and keys
    ifstream parms_stream("../client/fhe_setup/parameters", ios::binary);
    ifstream pk_stream("../client/fhe_setup/public_key", ios::binary);
    ifstream rlk_stream("../client/fhe_setup/relin_key", ios::binary);
    ifstream gk_stream("../client/fhe_setup/galois_key", ios::binary);

    EncryptionParameters parms;
    parms.load(parms_stream);
    parms_stream.seekg(0, parms_stream.beg);
    parms_stream.close();
    SEALContext context(parms);

    PublicKey public_key;
    public_key.load(context, pk_stream);
    pk_stream.seekg(0, pk_stream.beg);
    pk_stream.close();

    RelinKeys relin_keys;
    relin_keys.load(context, rlk_stream);
    rlk_stream.seekg(0, rlk_stream.beg);
    rlk_stream.close();

    GaloisKeys galois_keys;
    galois_keys.load(context, gk_stream);
    gk_stream.seekg(0, gk_stream.beg);
    gk_stream.close();

    Evaluator evaluator(context);
    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();

    // load model parameters
    vector<double> model_data;
    string model = model_dir;
    read_one_column(model_data, model);
    auto num_features = model_data.size();
    size_t num_sect = ceil((double)num_features / (double)slot_count);

    vector<vector<double>> w;
    vector<int>none_zero(num_sect,0);
    for(size_t i = 0; i < num_sect; i++)
    {
        size_t count = 0;
        for (size_t j = i*slot_count; j < (i+1)*slot_count&& j < num_features; j++)
        {
            if(abs(model_data[j]) < 1e-10)
    	    {   
                count++;
            }
        }
        if (count == slot_count)
            {
                none_zero[i] = 1;
            }
        //else
            // cout<<"i = "<<i<<endl;
    }
    // split the plain model into w
    split(model_data, num_sect, w);

    // load the ciphertext of the sample
    string fname = "../client/encrypted_data/bladder_cancer_patient_0001_encrypted";
    ifstream enc_data_stream(fname, ios::binary);

    vector<Ciphertext> x_encrypted;

    for (size_t k = 0; k < num_sect; k++)
    {
        Ciphertext ctx;
        ctx.load(context, enc_data_stream);
        x_encrypted.push_back(ctx);
    }

    enc_data_stream.seekg(0, enc_data_stream.beg);
    enc_data_stream.close();

    Ciphertext y_encrypted;

    // cout << "before plain-encrypted inner product..." << endl;

    double scale = SCALE;

    plain_encrypted_vector_inner_product(evaluator, encoder, scale, relin_keys, galois_keys,
     w, x_encrypted, slot_count, y_encrypted, none_zero);

    // cout << "after plain-encrypted inner product..." << endl;

    string enc_result_dir = "../server/result/bladder_cancer_patient_0001_encrypted_result";
    ofstream enc_result_stream(enc_result_dir, ios::binary);
    y_encrypted.save(enc_result_stream);
    enc_result_stream.close();
}
