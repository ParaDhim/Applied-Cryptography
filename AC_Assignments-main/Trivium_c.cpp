#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

//Trivium implmentation ; note 0 based indexing has been done, hence indexes have been written as i-1.
//Important Note: Kindly ensure no spaces in key and IV input, also ensure hex input starts with 0x.
// Group : Kartik Gupta(2021056) | Srimant Mohanty(2021207) | Alhad Sethi(2021445)

// Function to convert hexadecimal representation to binary representation, hexadecimal string should start with '0x'.
string hexToBin(const string& str) {
    // Map for hexadecimal to binary conversion
    map<char, string> hexToBinMap;
    
    // Mapping of hexadecimal numbers to binary notation
    hexToBinMap['0'] = "0000"; hexToBinMap['1'] = "0001"; hexToBinMap['2'] = "0010"; hexToBinMap['3'] = "0011";
    hexToBinMap['4'] = "0100"; hexToBinMap['5'] = "0101"; hexToBinMap['6'] = "0110"; hexToBinMap['7'] = "0111";
    hexToBinMap['8'] = "1000"; hexToBinMap['9'] = "1001"; hexToBinMap['A'] = "1010"; hexToBinMap['B'] = "1011";
    hexToBinMap['C'] = "1100"; hexToBinMap['D'] = "1101"; hexToBinMap['E'] = "1110"; hexToBinMap['F'] = "1111";
    hexToBinMap['a'] = "1010"; hexToBinMap['b'] = "1011"; hexToBinMap['c'] = "1100"; hexToBinMap['d'] = "1101";
    hexToBinMap['e'] = "1110"; hexToBinMap['f'] = "1111";

    // Check if the string starts with "0x", throw an invalid input error otherwise
    if (str.size() < 2 || str.substr(0, 2) != "0x") {
        throw invalid_argument("Hex string should start with '0x'");
    }

    string binaryString;
    /**
     * Iterate over the hexadecimal part of the string (excluding the "0x" prefix).
     * We iterate in a byte-wise manner, we first convert the byte into respective binary notation, for example
     * consider 0x80 00, in first iteration, we convert 80 to "1000 0000", and we add the binary string as the right most element 
     * in an empty string named "binaryString". We subsequently keep adding binary bits towards left of the previousy added bits in 
     * "binaryString".
     * For example, 0x80 00 10 becomes binaryString = 0001 0000 0000 0000 1000 0000 (gaps are for readability)
     * */
    for (size_t i = 2; i < str.size(); i+=2) {
        string byteStr;
        if (i + 1 < str.size()) {
            byteStr = hexToBinMap[str[i]] + hexToBinMap[str[i + 1]];
        } else {
            //Key and IV in trivium should be of length 20, which is even, if not- an error should be thrown
            throw invalid_argument("Hex string length is not even");
        }

        // Adding each new byte at the start(leftmost side) of binaryString.
        binaryString = byteStr + binaryString;
    }

    return binaryString;
}

// Function to convert a binary string to a hexadecimal string
string binToHex(const string& binary) {
    // Initialize the map using the insert method
    map<string, char> binToHexMap;
    
    binToHexMap.insert(make_pair("0000", '0'));
    binToHexMap.insert(make_pair("0001", '1'));
    binToHexMap.insert(make_pair("0010", '2'));
    binToHexMap.insert(make_pair("0011", '3'));
    binToHexMap.insert(make_pair("0100", '4'));
    binToHexMap.insert(make_pair("0101", '5'));
    binToHexMap.insert(make_pair("0110", '6'));
    binToHexMap.insert(make_pair("0111", '7'));
    binToHexMap.insert(make_pair("1000", '8'));
    binToHexMap.insert(make_pair("1001", '9'));
    binToHexMap.insert(make_pair("1010", 'A'));
    binToHexMap.insert(make_pair("1011", 'B'));
    binToHexMap.insert(make_pair("1100", 'C'));
    binToHexMap.insert(make_pair("1101", 'D'));
    binToHexMap.insert(make_pair("1110", 'E'));
    binToHexMap.insert(make_pair("1111", 'F'));

    string hexString = "";  // Initialize the result with an empty string.
    string temp = binary;

    // Ensure the binary string length is a multiple of 4 by padding with zeros
    while (temp.length() % 4 != 0) {
        temp = "0" + temp;
    }

    // Convert each group of 4 bits to the corresponding hexadecimal digit
    for (size_t i = 0; i < temp.length(); i += 4) {
        string fourBits = temp.substr(i, 4);
        hexString += binToHexMap[fourBits];
    }

    return hexString;
}

int main() {
    string key; //in hex format, 80 bits length, used to initialise the first 80 bits of A; should start with '0x'
    string IV; //in hex format, 80 bits length, used to initialise the first 80 bits of B; should start with '0x'
    string keyStream; //used to store binary output
    cout<<"Enter Key(In Hex; should start with 0x, without any spaces):\n";
    cin>>key;
    cout<<"Enter Initialization Vector(In Hex; should start with 0x, without any spaces):\n";
    cin>>IV;
    
    //converting hex to binary
    string key_binary = hexToBin(key);
    string IV_binary = hexToBin(IV);

    //representing each block using vectors, each intialised with 0
    vector<int> A(93,0);
    vector<int> B(84,0);
    vector<int> C(111,0);

    //Initialization of A using Key
    for(int i=0; i<key_binary.size(); i++){
        A[i] = key_binary[i] - '0';
    }

    //Initialization of B using IV
    for(int i=0; i<IV_binary.size(); i++){
        B[i] = IV_binary[i] - '0';
    }

    //Initialization of C
    C[109-1] = 1;
    C[110-1] = 1;
    C[111-1] = 1;

    //warm-up step
    // Goes on for 1152 iterations so that the keyStream generated afterwards seems neccessarily randomized
    for(int i=0; i<1152; i++){
        //t1, t2 and t3 are outputs of A, B and C respectively
        // In this code, X XOR Y has been written as (X+Y)%2 ie. (X+Y)mod 2.
        int t1 = (A[66-1] + A[93-1])%2;
        int t2 = (B[69-1] + B[84-1])%2;
        int t3 = (C[66-1] + C[111-1])%2;
        // FA, FB and FC are the feedbacks that go into A, B and C respectively
        int FA = ((C[109-1]*C[110-1] + t3)%2 + A[69-1])%2;
        int FB = ((A[91-1]*A[92-1] + t1)%2 + B[78-1])%2;
        int FC = ((B[82-1]*B[83-1] + t2)%2 + C[87-1])%2;
        // right shifting elements of A, B and C after each iteration
        for(int p=A.size()-2; p>=0; p--){
            A[p+1] = A[p];
        }
        for(int p=B.size()-2; p>=0; p--){
            B[p+1] = B[p];
        }
        for(int p=C.size()-2; p>=0; p--){
            C[p+1] = C[p];
        }
        // first element of A, B and C after shifting is set as FA, FB and FC respectively.
        A[0] = FA;
        B[0] = FB;
        C[0] = FC;
    }

    // keyStream generation phase, run for 512 iterations, outputs 512 bits which are stored in variable keyStream
    for(int i=0; i<512; i++){
        //t1, t2 and t3 are outputs of A, B and C respectively
        int t1 = (A[66-1] + A[93-1])%2;
        int t2 = (B[69-1] + B[84-1])%2;
        int t3 = (C[66-1] + C[111-1])%2;
        // z is ouput bit generated in each iteration, it is appended to keyStream
        int z = ((t1 + t2)%2 + t3)%2; // t1 XOR t2 XOR t3
        keyStream = keyStream + to_string(z);
        // FA, FB and FC are the feedbacks that go into A, B and C respectively
        int FA = ((C[109-1]*C[110-1] + t3)%2 + A[69-1])%2;
        int FB = ((A[91-1]*A[92-1] + t1)%2 + B[78-1])%2;
        int FC = ((B[82-1]*B[83-1] + t2)%2 + C[87-1])%2;
        // right shifting elements of A, B and C after each iteration
        for(int p=A.size()-2; p>=0; p--){
            A[p+1] = A[p];
        }
        for(int p=B.size()-2; p>=0; p--){
            B[p+1] = B[p];
        }
        for(int p=C.size()-2; p>=0; p--){
            C[p+1] = C[p];
        }
        // first element of A, B and C after shifting is set as FA, FB and FC respectively.
        A[0] = FA;
        B[0] = FB;
        C[0] = FC;
    }
    // reversing the keystream
    reverse(keyStream.begin(), keyStream.end());
    // conversion of keystream to hexadecimal format
    string hex = binToHex(keyStream);
    // reversing hex string
    reverse(hex.begin(), hex.end());

    // for every byte, swapping the first and second hex element
    for(int i=0; i<128; i+=2){
        int first = hex[i];
        int second = hex[i+1];
        hex[i] =  second;
        hex[i+1] = first;
    }
    hex = "0x" + hex; // appending "0x" prefix before hex output
    cout << "Hexadecimal representation: " << hex << endl; //printing hex output
    return 0;
}
