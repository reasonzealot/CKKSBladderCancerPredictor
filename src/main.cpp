#include <chrono>
#include "matrix.h"
#include "utils.h"
#include "client.h"
#include "server.h"


int main()
{

    string datadir = "../client/input_data/bladder_cancer_patient_0001.test";
    string modeldir = "../server/model/lasso.model";
    string resultdir = "../server/result/bladder_cancer_patient_0001_encrypted_result";

    auto global_beginning = std::chrono::high_resolution_clock::now();


    auto local_beginning = std::chrono::high_resolution_clock::now();
    cout << "   + Client: key generation ... " << endl;
    client_key_gen();
    auto local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   + Client: key generation ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;

    local_beginning = std::chrono::high_resolution_clock::now();
    cout << "   + Client: encryption of patient data ... " << endl;
    client_encrypt_data(datadir);
    local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   + Client: encryption of patient data ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;


    local_beginning = std::chrono::high_resolution_clock::now();
    cout << "   * Server: evaluation for patient data ... " << endl;
    server_evaluation(modeldir);
    local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   * Server: evaluation for patient data ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;

    local_beginning = std::chrono::high_resolution_clock::now();
    cout << "   + Client: decryption of the result ... " << endl;
    client_decrypt_result(resultdir);
    local_timing = std::chrono::high_resolution_clock::now() - local_beginning;
    cout << "   + Client: decryption of the result ... costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(local_timing).count() / 1e6 << " seconds." << endl;

    auto global_timing = std::chrono::high_resolution_clock::now() - global_beginning;

    cout << endl
         << "The total timing costs: " << (double)std::chrono::duration_cast<std::chrono::microseconds>(global_timing).count() / 1e6 << " seconds." << endl;
    cout << endl
         << "The total RAM used: " << (double)(memory_usage() / 1e6 + 1) << " MB" << endl;
    
     /*
     vector<double> model_data;
     string model = modeldir;
     read_one_column(model_data, model);
     vector<double>usr_data;
     string data = datadir;
     read_one_column(usr_data,data);
     usr_data.push_back(1.0);
     double y=0;
     linear_eval_plain(model_data,usr_data,y);
     */

    return 0;
}
