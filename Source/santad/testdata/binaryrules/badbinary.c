#include <stdio.h>

int main(int argc, char* argv[]) {
  const char* evil =
      "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  printf("%s", evil);
  return 0;
}
