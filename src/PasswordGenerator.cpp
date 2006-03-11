#include "PasswordGenerator.hpp"

#include <boost/nondet_random.hpp>

#include "Error.hpp"

namespace KAdm5
{

PasswordGenerator::PasswordGenerator()
{
	CharacterClass cc[] = PWGEN_DEFAULT_CHARACTER_CLASSES;

	for (int i=0; i < PWGEN_DEFAULT_CHARACTER_CLASSES_COUNT; i++) {
		_characterClasses.push_back(cc[i]);
	}
}


PasswordGenerator::PasswordGenerator(const vector<CharacterClass>& characterClasses)
	:	_characterClasses(characterClasses)
{
	if (!characterClasses.size()) {
		throw ParamError(0);
	}
}


string PasswordGenerator::randomPassword() const
{
	boost::random_device rng;
	string random_chars;

	// Generate a list of random characters with the specified frequencies.
	for (int i=0; i < _characterClasses.size(); i++) {
		for (int j=0; j < _characterClasses[i].frequency; j++) {
			random_chars += _characterClasses[i].charset[ rng() % _characterClasses[i].charset.size() ];
		}
	}
	
	string pw;
	
	// Put the random characters at random positions in the password.
	while (random_chars.size()) {
		string::iterator it = random_chars.begin() + (rng() % random_chars.size());
		pw += *it;
		random_chars.erase(it);
	}
	
	return pw;
}


}
