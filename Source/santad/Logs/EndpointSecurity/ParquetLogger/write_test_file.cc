#include <iostream>
#include "Source/santad/Logs/EndpointSecurity/ParquetLogger/gen/cpp_api.rs.h"

int main() {
    auto args = pedro::wire::table_args_new("name", "./path");
    pedro::wire::table_args_add_column(*args, "column", pedro::wire::CxxColumnType::Int32);
    try {
        auto table = pedro::wire::table_new(std::move(args));
        std::cout << "Success!" << std::endl;
    } catch (std::exception &e) {
        std::cout << "Error!" << std::endl;
        std::cout << e.what() << std::endl;
    }
    return 0;
}
