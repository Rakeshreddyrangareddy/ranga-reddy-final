#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>

using namespace std;

// Function prototypes for functional decomposition
vector<uint32_t> preprocess(const string &input);
void process_chunk(const vector<uint32_t> &chunk, uint32_t hash[]);
string compute_sha256(const string &input);
string read_file(const string &filename);

// SHA-256 Constants
const uint32_t K[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Helper functions
uint32_t right_rotate(uint32_t value, unsigned int count) {
    return (value >> count) | (value << (32 - count));
}

// Preprocess the input message (Padding)
vector<uint32_t> preprocess(const string &input) {
    vector<uint32_t> result;
    size_t original_length = input.size() * 8;
    
    // Append the bit '1' to the message
    stringstream ss;
    ss << input;
    ss << static_cast<unsigned char>(0x80); // Append a single '1' bit

    // Pad with zeros
    while ((ss.str().size() * 8) % 512 != 448) {
        ss << static_cast<unsigned char>(0x00);
    }

    // Append original length as 64-bit big-endian
    for (int i = 7; i >= 0; --i) {
        ss << static_cast<unsigned char>((original_length >> (i * 8)) & 0xFF);
    }

    // Convert the string to a vector of 32-bit words (big-endian)
    string padded_message = ss.str();
    for (size_t i = 0; i < padded_message.size(); i += 4) {
        uint32_t word = 0;
        for (size_t j = 0; j < 4; ++j) {
            word = (word << 8) | static_cast<unsigned char>(padded_message[i + j]);
        }
        result.push_back(word);
    }

    return result;
}

// Process each 512-bit chunk of the message
void process_chunk(const vector<uint32_t> &chunk, uint32_t hash[]) {
    uint32_t w[64];
    
    // Copy chunk into first 16 words of the message schedule array
    for (int i = 0; i < 16; ++i) {
        w[i] = chunk[i];
    }
    
    // Extend the first 16 words into the remaining 48 words of the message schedule array
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    
    // Initialize working variables to current hash value
    uint32_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
    uint32_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];
    
    // Compression function main loop
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    
    // Add the compressed chunk to the current hash value
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

// Main function to compute the SHA-256 hash of an input string
string compute_sha256(const string &input) {
    // Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
    uint32_t hash[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Preprocess the input
    vector<uint32_t> padded_message = preprocess(input);

    // Process the message in successive 512-bit chunks
    for (size_t i = 0; i < padded_message.size(); i += 16) {
        vector<uint32_t> chunk(padded_message.begin() + i, padded_message.begin() + i + 16);
        process_chunk(chunk, hash);
    }

    // Produce the final hash as a hexadecimal string
    stringstream result;
    for (int i = 0; i < 8; ++i) {
        result << hex << setfill('0') << setw(8) << hash[i];
    }

    return result.str();
}

// Function to read the content of a file
string read_file(const string &filename) {
    ifstream file(filename);
    if (!file) {
        cerr << "Error: Could not open file " << filename << endl;
        exit(1);
    }

    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// Main function
int main() {
    string filename = "ranga_reddy_final.txt";
    string file_content = read_file(filename);

    // Compute and output the SHA-256 hash of the file content
    string sha256_hash = compute_sha256(file_content);
    cout << "SHA-256 Hash: " << sha256_hash << endl;

    return 0;
}
