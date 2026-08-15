cmake_minimum_required(VERSION 3.10)
project(DSS_Security_Project C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options de compilation
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# Trouver les threads POSIX (pthread)
find_package(Threads REQUIRED)

# Exécutable : Port Scanner en C
add_executable(c_port_scanner c_scanner/port_scanner.c)
target_link_libraries(c_port_scanner PRIVATE Threads::Threads)

# Exécutable : Exercice variable C (pour les fondations C du dépôt)
add_executable(variable variable.c)

# Activation des tests CTest pour le workflow GitHub Actions
enable_testing()

add_test(NAME TestVariableCommand COMMAND variable)
add_test(NAME TestScannerHelp COMMAND c_port_scanner -h)
