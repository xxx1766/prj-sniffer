#include "sniff.h"
#include <iostream>

int main() {
	Sniff *sniff = new Sniff();
	sniff->start();
	return 0;
}

