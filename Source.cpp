// Brute Force password cracker implemented by Jonah McElfatrick for CMP202 Data Structures and Algorithms 2
#include <iostream>
#include <string>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include "md5.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-md5-function
#include "sha224.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha224-function
#include "sha256.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha256-function
#include "sha384.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha384-function
#include "sha512.h" // NOT MY OWN WORK, THIS FILE WAS TAKEN FROM http://www.zedwood.com/article/cpp-sha512-function

using namespace std;

// Import clock
using std::chrono::duration_cast;
using std::chrono::milliseconds;

// Define the alias "the_clock" for the clock type we're going to use.
typedef std::chrono::steady_clock the_clock;

// Mutex for when calculating the hash
mutex hash_mutex;

// Mutex for when displaying the current attempted password
mutex cout_mutex;

// Counter condition variable to count the number of attempts been carried out
condition_variable counter_cv;
mutex counter_mutex;
bool counter_bool;

// Bool to identify wheither the password has been found or not
bool done = false;

// String for the found password
string FoundPassword;

// Counter
int counter = 0;

// Method of found
string method;


// Used method
string hashMethod;

// Uppercase letters array
const char CapitaLetters[26] =
{
	'A', 'B', 'C', 'D', 'E', 'F', 'G',
	'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U',
	'V', 'W', 'X', 'Y', 'Z'
};

// Lowercase letters array
const char LowerCaseLetters[26] =
{
	'a', 'b', 'c', 'd', 'e', 'f', 'g',
	'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u',
	'v', 'w', 'x', 'y', 'z'
};

// Symbols array
const char Symbols[22] =
{
	'!','£','$','%','^','&','*','(',')'
	,'@','~','#','|','?','¬','`','{',
	'}','[',']',';',':'
};

// Numbers array
const char Numbers[10] =
{
	'1','2','3','4','5','6','7','8','9','0'
};

// Takes each line in the word file, hashes it then compares it to the entered hash to see if they match
// If they match then the password has been found, else it continues on till the end of the file
void DictionaryAttack(string filename, string inputHash, int hashChoice, int display) {
	// Variable for the contents of the file
	string contents;

	// Opens the text file for reading
	ifstream file(filename, ios_base::binary);

	// Check to see if the file was sucessfully opened
	if (!file.good()) {
		cout << "Unable to open Text File";
		system("pause");
	}
	else {
		// Takes each line in the textfile and hashes the contents, then compares it to the entered hash
		while (file >> contents && !done) {
			// Notify the counter condition variable to allow the addition of another attempt to the counter variable
			counter_bool = true;
			counter_cv.notify_one();

			// Check to see if the user wants to print out current password being attempted
			// Mutex's used to allow for a clean output on which password is being attempted
			if (display == 1) {
				cout_mutex.lock();
				cout << contents << endl;
				cout_mutex.unlock();
			}
			
			// Initialise hash variable to store the hashed attempted password
			string hash = "";

			// Hash the password using MD5
			hash_mutex.lock();
			hash = md5(contents);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputed hash in MD5
			if (hash == inputHash) {
				hashMethod = "MD5";
				cout << endl << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = contents;
				method = "Dictionary";
				cout_mutex.unlock();
			}

			// Hash the password using sha256
			hash_mutex.lock();
			hash = sha256(contents);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA256
			if (hash == inputHash) {
				hashMethod = "SHA256";
				cout << endl << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = contents;
				method = "Dictionary";
				cout_mutex.unlock();
			}

			// Hash the password using sha224
			hash_mutex.lock();
			hash = sha224(contents);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA224
			if (hash == inputHash) {
				hashMethod = "SHA224";
				cout << endl << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = contents;
				method = "Dictionary";
				cout_mutex.unlock();
			}

			// Hash the password using sha384
			hash_mutex.lock();
			hash = sha384(contents);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA384
			if (hash == inputHash) {
				hashMethod = "SHA384";
				cout << endl << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = contents;
				method = "Dictionary";
				cout_mutex.unlock();
			}

			// Hash the password using sha512
			hash_mutex.lock();
			hash = sha512(contents);
			hash_mutex.unlock();

			// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA512
			if (hash == inputHash) {
				hashMethod = "SHA512";
				cout << endl << hash << endl;
				cout_mutex.lock();
				done = true;
				FoundPassword = contents;
				method = "Dictionary";
				cout_mutex.unlock();
			}
		}
	}
	// Closes the input textfile
	file.close();
	return;
}

// Tries every itteration or possibility from lowercase letters, uppercase letters, numbers and symbols. Hashes these itterations and then compares them to the entered hash value
// If the calculated hash is equal to the entered hash then the password has been found, else it continues on till the end of the possible itterations
// For each thread running this function they are calculating it for different lengths, for example thread one will calculate for a password string length of 1
// thread two will calculate for a password string length of 2, thread three will calculate for a password string length of 3 and so on.
void BruteForce(int stringlength, string s, string inputHash, int hashChoice, int display) {
	// Check to see if the password has been found, if so will start the return process on all itterations of the function
	if (done) return;

	string pwordattempt;

	// Checks to see if the attempte password length for the thread has been reached to then check if the attempted password is equal to the actual password
	if (stringlength == 0)
	{
		// Notify the counter condition variable to allow the addition of another attempt to the counter variable
		counter_bool = true;
		counter_cv.notify_one();

		// Check to see if the user wants to print out current password being attempted
		// Mutex's used to allow for a clean output on which password is being attempted
		if (display == 1) {
			cout_mutex.lock();
			cout << s << endl;
			cout_mutex.unlock();
		}

		// Initialise hash variable to store the hashed attempted password
		string hash = "";

		// Hash the password using MD5
		hash_mutex.lock();
		hash = md5(s);
		hash_mutex.unlock();

		// Checks to see if the current hashed attempted password is equal to the inputed hash in MD5
		if (hash == inputHash) {
			hashMethod = "MD5";
			cout << endl << hash << endl;
			cout_mutex.lock();
			done = true;
			FoundPassword = s;
			method = "Brute Force";
			cout_mutex.unlock();
		}

		// Hash the password using sha224
		hash_mutex.lock();
		hash = sha224(s);
		hash_mutex.unlock();

		// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA224
		if (hash == inputHash) {
			hashMethod = "SHA224";
			cout << endl << hash << endl;
			cout_mutex.lock();
			done = true;
			FoundPassword = s;
			method = "Brute Force";
			cout_mutex.unlock();
		}

		// Hash the password using sha256
		hash_mutex.lock();
		hash = sha256(s);
		hash_mutex.unlock();

		// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA256
		if (hash == inputHash) {
			hashMethod = "SHA256";
			cout << endl << hash << endl;
			cout_mutex.lock();
			done = true;
			FoundPassword = s;
			method = "Brute Force";
			cout_mutex.unlock();
		}

		// Hash the password using sha384
		hash_mutex.lock();
		hash = sha384(s);
		hash_mutex.unlock();

		// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA384
		if (hash == inputHash) {
			hashMethod = "SHA384";
			cout << endl << hash << endl;
			cout_mutex.lock();
			done = true;
			FoundPassword = s;
			method = "Brute Force";
			cout_mutex.unlock();
		}

		// Hash the password using sha512
		hash_mutex.lock();
		hash = sha256(s);
		hash_mutex.unlock();

		// Checks to see if the current hashed attempted password is equal to the inputed hash in SHA512
		if (hash == inputHash) {
			hashMethod = "SHA512";
			cout << endl << hash << endl;
			cout_mutex.lock();
			done = true;
			FoundPassword = s;
			method = "Brute Force";
			cout_mutex.unlock();
		}
		
		return;
	}

	for (int i = 0; i < 26 && !done; i++) // iterate through alphabet
	{
		// Append new character onto the string
		// Recursively call function again untill string has reached its length
		// Loop for lowercase letters
		pwordattempt = s + LowerCaseLetters[i];
		BruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for capital letters
	for (int j = 0; j < 26 && !done; j++) {
		pwordattempt = s + CapitaLetters[j];
		BruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for symbols
	for (int x = 0; x < 22 && !done; x++) {
		pwordattempt = s + Symbols[x];
		BruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}

	// Loop for numbers
	for (int y = 0; y < 10 && !done; y++) {
		pwordattempt = s + Numbers[y];
		BruteForce(stringlength - 1, pwordattempt, inputHash, hashChoice, display);
	}
}

// Simple function to check if an integer is within a certain range
int validateInt(int min, int max, int choice) {
	while (choice < min || choice > max) {
		cout << "Invalid Input" << endl;
		cout << "Please enter a value from the range above: " << endl << ">> ";
		cin >> choice;
		cout << endl;
	}
	return choice;
}

// Recieve the choice of which hashing algorithm the password was hashed with
int RecieveChoiceInput() {
	int choice;
	cout << "Please enter the type of hash you are wanting to crack" << endl << "1:MD5" << endl << "2:sha256" << endl << ">> ";
	cin >> choice;
	cout << endl;
	validateInt(1, 2, choice);
	return choice;
}

// Recieve the hash that is trying to be cracked
string RecieveHashInput() {
	string hash;
	cout << "Please enter the hash you would like to crack: " << endl << ">> ";
	cin >> hash;
	cout << endl;
	return hash;
}

// Recive the filename for the wordlist used in the dictionary attack
string RecieveFilename() {
	string filename;
	cout << "Please enter the filename with the correct extension for the dictionary attack: " << endl << ">> ";
	cin >> filename;
	cout << endl;
	return filename;
}

// Function for recieving the number of threads that will run depending on how many characters the user wants to try and crack the password for
int RecieveThreads() {
	int threadNumber;
	int choice;
	// Gives the user the choice to use the maximum number of threads available by the computers CPU
	// Or to use a specified number of threads
	cout << "Please select from the following: " << endl << "1: Specify number of threads" << endl << "2: Detect Maximum threads" << endl << ">> ";
	cin >> choice;
	// Validate choice is one from the list above
	validateInt(1, 2, choice);
	
	if (choice == 1) {
		cout << "Please enter the number of characters you would like to try to crack: " << endl << ">> ";
		cin >> threadNumber;
		cout << endl;

		// Validate the input is no more than 6 characters long
		validateInt(1, 10, threadNumber);

		// Returning threadNumber + 2 as there is 2 threads needed extra, one for the dictionary
		// attack and one to run the counter function to count the number of times a attempt has been made to crack the password
		threadNumber += 2;
	}
	else {
		threadNumber = thread::hardware_concurrency();
	}

	return threadNumber;
}

// Fucntion to recieve the choice to display the current attempted password
int recieveDisplayChoice() {
	int choice;
	cout << "Would you like to view all attempted password? (1 for Yes or 0 for No)" << endl << "Please note this will increase the time taken to crack the password drastically" << endl << ">> ";
	cin >> choice;
	cout << endl;
	choice = validateInt(0, 1, choice);
	return choice;
}

// Function to record the number of attempts that have been made to crack the entered hash
void numberCounter() {
	while (!done)
	{
		unique_lock<mutex> mylock(counter_mutex);
		while (!done && counter_bool == false) {
			counter_cv.wait(mylock);
		}
		if (done)
			return;
		counter += 1;
		counter_bool = false;
	}
	return;
}


int main()
{
	//Initialise variable for storing the filename of the wordlist being used
	string filename;

	// Choice of which hash is being used
	int hashChoice = 0;

	// The inputed hash that is the target goal to crack
	string inputHash = "";

	// Number of attemtps to crack the password
	int attempts;

	// Length of the string being attempted as the password
	int stringlength = 1;
	
	// Number of threads that are being initiated 
	int threadNumber;

	// Choice to display attempted passwords or not
	int display;

	// Recieve the which hashing algorithm is being used
	//hashChoice = RecieveChoiceInput();

	// Recieve the hash that is being broken
	inputHash = RecieveHashInput();

	// Recieve the name of the text file that is being used in the dictionary attack
	filename = RecieveFilename();

	// Recieve the choice to display the attempted passwords or not
	display = recieveDisplayChoice();

	// Recieve the number of threads to be initiated
	threadNumber = RecieveThreads();

	cout << "Initialising password crack...";

	// Start the clock 
	the_clock::time_point start = the_clock::now();

	// Initialise vector of threads
	vector<thread> tvector = {};

	// Initialise the thread to run the counter loop to count the number of attempts to crack the password
	tvector.push_back(thread(numberCounter));

	// Initialising threads each cracking the password for a different length
	while (stringlength < (threadNumber - 1)) {
		tvector.push_back(thread(BruteForce, stringlength, "", inputHash, hashChoice, display));
		stringlength++;
	}

	//Initialise thread for Dictionary attack
	tvector.push_back(thread(DictionaryAttack, filename, inputHash, hashChoice, display));

	// Join all working threads 
	for (int i = 1; i < threadNumber; i++) {
		tvector[i].join();
	}

	// Display the cracked password if found and the number of tries to crack it
	if (done) {
		cout << "Cracked Password: " << FoundPassword << endl;
		cout << "Number of attempts to crack the password: " << counter << endl;
	}
	//Display password not found
	else {
		cout << "Password not found" << endl;
	}
	the_clock::time_point end = the_clock::now();
	// End the clock

	// Compute and display the difference between the start and end times in milliseconds
	auto time_taken = duration_cast<milliseconds>(end - start).count();
	cout << "Cracking the password took " << time_taken << " ms. " << "It was using the " << hashMethod << " hash method. " << "It was found using the " << method << " attack." << endl;

	// Notify and join the thread that is running the counter loop to count the number of password attempts
	counter_cv.notify_one();
	(tvector.front()).join();

	system("pause");
	return 0;
}