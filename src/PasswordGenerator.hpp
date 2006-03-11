#ifndef PASSWORDGENERATOR_HPP_
#define PASSWORDGENERATOR_HPP_

#include <string>
#include <vector>

#define PWGEN_DEFAULT_CHARACTER_CLASSES { \
	{ "abcdefghijklmnopqrstuvwxyz", 7 }, \
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 2 }, \
	{ "@$%&*()-+=:,/<>1234567890" , 1 }, \
}
#define PWGEN_DEFAULT_CHARACTER_CLASSES_COUNT 3


namespace KAdm5
{
using std::string;
using std::vector;


struct CharacterClass {
	string charset;
	int frequency;
};

// TODO Refactor this class, maybe remove it altogether
// and use a global function?
class PasswordGenerator
{
public:
	PasswordGenerator();
	PasswordGenerator(const std::vector<CharacterClass>&);
	string randomPassword() const;

private:
	vector<CharacterClass> _characterClasses;
};

}

#endif /*PASSWORDGENERATOR_HPP_*/
