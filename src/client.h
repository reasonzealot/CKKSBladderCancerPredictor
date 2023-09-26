#ifndef CLIENT_H
#define CLIENT_H

#include <stdio.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include "seal/seal.h"
#include "matrix.h"
#include "utils.h"


using namespace std;


void client_key_gen();

void client_encrypt_data(string &data_dir);

void client_decrypt_result(string &result_dir);

#endif /* CLIENT_H */
